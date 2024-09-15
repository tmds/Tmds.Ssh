using Azure.Security.KeyVault.Keys.Cryptography;
using System;
using System.Security.Cryptography;
using AzureSignatureAlgorithm = Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm;

namespace Tmds.Ssh.AzureKeyExample;

sealed class AzureRsaKey : RSA
{
    private readonly CryptographyClient _cryptoClient;
    private readonly RSAParameters _publicParameters;

    public AzureRsaKey(CryptographyClient client, RSAParameters publicParameters)
    {
        KeySizeValue = publicParameters.Modulus!.Length * 8;
        _cryptoClient = client;
        _publicParameters = publicParameters;
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException("Cannot export private parameters");
        }

        return _publicParameters;
    }

    public override void ImportParameters(RSAParameters parameters)
        => throw new NotImplementedException();

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding != RSASignaturePadding.Pkcs1)
        {
            throw new CryptographicException($"Unsupported padding {padding}");
        }

        AzureSignatureAlgorithm sigAlgo = hashAlgorithm.Name switch
        {
            "SHA256" => AzureSignatureAlgorithm.RS256,
            "SHA512" => AzureSignatureAlgorithm.RS512,
            _ => throw new CryptographicException($"Unsupported hash algorithm {hashAlgorithm.Name}"),
        };

        byte[] res = _cryptoClient.Sign(sigAlgo, hash).Signature;
        return res;
    }
}
