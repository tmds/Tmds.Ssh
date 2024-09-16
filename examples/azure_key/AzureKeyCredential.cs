using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AzureSignatureAlgorithm = Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm;

namespace Tmds.Ssh.AzureKeyExample;

sealed class AzureKeyCredential : PrivateKeyCredential
{
    public AzureKeyCredential(TokenCredential credential, KeyVaultKey key) :
        base((c) => GetAzureKeyAsync(credential, key, c), $"azure:{key.Id}")
    { }

    private static ValueTask<Key> GetAzureKeyAsync(
        TokenCredential credential,
        KeyVaultKey key,
        CancellationToken cancellationToken = default)
    {
        CryptographyClient azureClient = new CryptographyClient(key.Id, credential);

        Key privateKey;
        if (key.KeyType == KeyType.Rsa)
        {
            RSAParameters pubParams = key.Key.ToRSA(includePrivateParameters: false)
                .ExportParameters(false);

            privateKey = new Key(new AzureRsaKey(azureClient, pubParams, cancellationToken));
        }
        else if (key.KeyType == KeyType.Ec)
        {
            ECParameters pubParams = key.Key.ToECDsa(includePrivateParameters: false)
                .ExportParameters(false);

            AzureSignatureAlgorithm sigAlgo = key.Key.CurveName.ToString() switch
            {
                "P-256" => AzureSignatureAlgorithm.ES256,
                "P-384" => AzureSignatureAlgorithm.ES384,
                "P-521" => AzureSignatureAlgorithm.ES512,
                _ => throw new NotImplementedException($"Unsupported curve {key.Key.CurveName}"),
            };

            privateKey = new Key(new AzureECDsaKey(azureClient, pubParams, sigAlgo, cancellationToken));
        }
        else
        {
            throw new NotImplementedException($"Unsupported Azure key type {key.KeyType}");
        }

        return ValueTask.FromResult(privateKey);
    }
}
