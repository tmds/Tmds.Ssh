using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AzureSignatureAlgorithm = Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm;

namespace Tmds.Ssh.AzureKeyExample;

sealed class AzureKeyCredential : PrivateKeyCredential
{
    public AzureKeyCredential(string vaultName, string keyName) :
        base((c) => GetAzureKey(vaultName, keyName, c), $"Azure Key Vault: {vaultName}/{keyName}")
    { }

    public static async ValueTask<string> GetAzurePubKey(string vaultName, string keyName)
    {
        (var _, KeyVaultKey key) = await GetKeyVaultKey(vaultName, keyName);

        if (key.KeyType == KeyType.Rsa)
        {
            RSAParameters pubParams = key.Key.ToRSA(includePrivateParameters: false)
                .ExportParameters(false);
            return GetRsaPubKey(pubParams);
        }
        else if (key.KeyType == KeyType.Ec)
        {
            ECParameters pubParams = key.Key.ToECDsa(includePrivateParameters: false)
                .ExportParameters(false);
            return GetEcdsaPubKey(pubParams);
        }
        else
        {
            throw new NotImplementedException($"Unsupported Azure key type {key.KeyType}");
        }
    }

    private static async ValueTask<Key> GetAzureKey(string vaultName, string keyName, CancellationToken cancellationToken = default)
    {
        (TokenCredential cred, KeyVaultKey key) = await GetKeyVaultKey(vaultName, keyName);

        if (key.KeyType == KeyType.Rsa)
        {
            CryptographyClient azureClient = new CryptographyClient(key.Id, cred);
            RSAParameters pubParams = key.Key.ToRSA(includePrivateParameters: false)
                .ExportParameters(false);

            return new Key(new AzureRsaKey(azureClient, pubParams));
        }
        else if (key.KeyType == KeyType.Ec)
        {
            AzureSignatureAlgorithm sigAlgo = key.Key.CurveName.ToString() switch
            {
                "P-256" => AzureSignatureAlgorithm.ES256,
                "P-384" => AzureSignatureAlgorithm.ES384,
                "P-521" => AzureSignatureAlgorithm.ES512,
                _ => throw new NotImplementedException($"Unsupported curve {key.Key.CurveName}"),
            };

            CryptographyClient azureClient = new CryptographyClient(key.Id, cred);
            ECParameters pubParams = key.Key.ToECDsa(includePrivateParameters: false)
                .ExportParameters(false);

            return new Key(new AzureECDsaKey(azureClient, pubParams, sigAlgo));
        }
        else
        {
            throw new NotImplementedException($"Unsupported Azure key type {key.KeyType}");
        }
    }

    private static async ValueTask<(TokenCredential, KeyVaultKey)> GetKeyVaultKey(string vaultName, string keyName)
    {
        DefaultAzureCredential cred = new(includeInteractiveCredentials: true);

        string keyVaultUrl = $"https://{vaultName}.vault.azure.net/";
        KeyClient keyClient = new KeyClient(new Uri(keyVaultUrl), cred);
        return (cred, await keyClient.GetKeyAsync(keyName));
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
