using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Tmds.Ssh.AzureKeyExample;

class Program
{
    static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || (args[0] != "ssh" && args[0] != "print_pub_key"))
        {
            Console.Error.WriteLine("Usage: azure_key {ssh,print_pub_key} <vaultName> <keyName>");
            return 255;
        }

        string action = args[0];
        if (args.Length < 3)
        {
            if (action == "ssh")
            {
                Console.Error.WriteLine("Usage: azure_key ssh <vaultName> <keyName> [<destination>] [<command>]");
            }
            else
            {
                Console.Error.WriteLine("Usage: azure_key print_pub_key <vaultName> <keyName>");
            }
            return 255;
        }

        string vaultName = args[1];
        string keyName = args[2];

        DefaultAzureCredential cred = new(includeInteractiveCredentials: true);
        string keyVaultUrl = $"https://{vaultName}.vault.azure.net/";
        KeyClient keyClient = new KeyClient(new Uri(keyVaultUrl), cred);
        KeyVaultKey key = await keyClient.GetKeyAsync(keyName);

        if (action == "print_pub_key")
        {
            return PrintPublicKeyAsync(key);
        }
        else
        {
            string destination = args.Length >= 4 ? args[3] : "localhost";
            string command = args.Length >= 5 ? args[4] : "echo 'hello world'";
            return await SshExecAsync(cred, key, destination, command);
        }
    }

    private static int PrintPublicKeyAsync(KeyVaultKey key)
    {
        string pubKey;
        if (key.KeyType == KeyType.Rsa)
        {
            RSAParameters pubParams = key.Key.ToRSA(includePrivateParameters: false)
                .ExportParameters(false);
            pubKey = GetRsaPubKey(pubParams);
        }
        else if (key.KeyType == KeyType.Ec)
        {
            ECParameters pubParams = key.Key.ToECDsa(includePrivateParameters: false)
                .ExportParameters(false);
            pubKey = GetEcdsaPubKey(pubParams);
        }
        else
        {
            throw new NotImplementedException($"Unsupported Azure key type {key.KeyType}");
        }

        Console.WriteLine(pubKey);
        return 0;
    }

    private static async Task<int> SshExecAsync(TokenCredential credential, KeyVaultKey key, string destination, string command)
    {
        SshClientSettings clientSettings = new SshClientSettings(destination)
        {
            Credentials = [new AzureKeyCredential(credential, key)],
        };
        using SshClient client = new SshClient(clientSettings);

        using var process = await client.ExecuteAsync(command);
        Task[] tasks = new[]
        {
            PrintToConsole(process),
            ReadInputFromConsole(process)
        };
        Task.WaitAny(tasks);
        PrintExceptions(tasks);

        return await process.GetExitCodeAsync();

        static async Task PrintToConsole(RemoteProcess process)
        {
            await foreach ((bool isError, string line) in process.ReadAllLinesAsync())
            {
                Console.WriteLine(line);
            }
        }

        static async Task ReadInputFromConsole(RemoteProcess process)
        {
            // note: Console doesn't have an async ReadLine that accepts a CancellationToken...
            await Task.Yield();
            var cancellationToken = process.ExecutionAborted;
            while (!cancellationToken.IsCancellationRequested)
            {
                string? line = Console.ReadLine();
                if (line == null)
                {
                    break;
                }
                await process.WriteLineAsync(line);
            }
        }

        static void PrintExceptions(Task[] tasks)
        {
            foreach (var task in tasks)
            {
                Exception? innerException = task.Exception?.InnerException;
                if (innerException is not null)
                {
                    System.Console.WriteLine("Exception:");
                    Console.WriteLine(innerException);
                }
            }
        }
    }

    private static string GetRsaPubKey(RSAParameters pubParams)
    {
        byte[] n = pubParams.Modulus!;
        byte[] e = pubParams.Exponent!;

        // If the modulus has the highest bit set, we need to pad it with a 0
        // byte.
        int padding = 0;
        if ((n[0] & 0x80) != 0)
        {
            padding = 1;
        }

        Span<byte> keyData = stackalloc byte[4 + 7 + 4 + e.Length + 4 + padding + n.Length];
        BinaryPrimitives.WriteInt32BigEndian(keyData, 7);
        Encoding.ASCII.GetBytes("ssh-rsa", keyData.Slice(4));
        BinaryPrimitives.WriteInt32BigEndian(keyData.Slice(11), e.Length);
        e.CopyTo(keyData.Slice(15, e.Length));
        BinaryPrimitives.WriteInt32BigEndian(keyData.Slice(15 + e.Length), n.Length + padding);
        keyData[19 + e.Length] = 0;
        n.CopyTo(keyData.Slice(19 + e.Length + padding));

        return $"ssh-rsa {Convert.ToBase64String(keyData)}";
    }

    private static string GetEcdsaPubKey(ECParameters pubParams)
    {
        byte[] x = pubParams.Q.X!;
        byte[] y = pubParams.Q.Y!;

        string curveName = pubParams.Curve.Oid?.FriendlyName switch
        {
            "ECDSA_P256" => "nistp256",
            "ECDSA_P384" => "nistp384",
            "ECDSA_P521" => "nistp521",
            _ => throw new NotImplementedException($"Unsupported ECDSA curve {pubParams.Curve.Oid?.FriendlyName}"),
        };
        string keyType = $"ecdsa-sha2-{curveName}";

        Span<byte> keyData = stackalloc byte[4 + keyType.Length + 4 + curveName.Length + 4 + 1 + x.Length + y.Length];
        BinaryPrimitives.WriteInt32BigEndian(keyData, keyType.Length);
        Encoding.ASCII.GetBytes(keyType, keyData.Slice(4));
        BinaryPrimitives.WriteInt32BigEndian(keyData.Slice(4 + keyType.Length), curveName.Length);
        Encoding.ASCII.GetBytes(curveName, keyData.Slice(8 + keyType.Length));
        BinaryPrimitives.WriteInt32BigEndian(keyData.Slice(8 + keyType.Length + curveName.Length), x.Length + y.Length + 1);
        keyData[12 + keyType.Length + curveName.Length] = 0x04;
        x.CopyTo(keyData.Slice(13 + keyType.Length + curveName.Length));
        y.CopyTo(keyData.Slice(13 + keyType.Length + curveName.Length + x.Length));

        return $"{keyType} {Convert.ToBase64String(keyData)}";
    }
}
