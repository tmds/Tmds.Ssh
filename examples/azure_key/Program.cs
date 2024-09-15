using System;
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

        if (action == "print_pub_key")
        {
            return await PrintPublicKey(vaultName, keyName);
        }
        else
        {
            string destination = args.Length >= 4 ? args[3] : "localhost";
            string command = args.Length >= 5 ? args[4] : "echo 'hello world'";
            return await SshExec(vaultName, keyName, destination, command);
        }
    }

    private static async Task<int> PrintPublicKey(string vaultName, string keyName)
    {
        string pubKey = await AzureKeyCredential.GetAzurePubKey(vaultName, keyName);
        Console.WriteLine(pubKey);
        return 0;
    }

    private static async Task<int> SshExec(string vaultName, string keyName, string destination, string command)
    {
        SshClientSettings clientSettings = new SshClientSettings(destination)
        {
            Credentials = [new AzureKeyCredential(vaultName, keyName)],
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

        return process.ExitCode;

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
}
