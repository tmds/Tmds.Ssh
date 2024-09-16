using Azure.Security.KeyVault.Keys.Cryptography;
using System;
using System.Security.Cryptography;
using System.Threading;
using AzureSignatureAlgorithm = Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm;

namespace Tmds.Ssh.AzureKeyExample;

sealed class AzureRsaKey : RSA
{
    private readonly CryptographyClient _cryptoClient;
    private readonly RSAParameters _publicParameters;
    private readonly CancellationToken _cancellationToken;

    public AzureRsaKey(
        CryptographyClient client,
        RSAParameters publicParameters,
        CancellationToken cancellationToken)
    {
        KeySizeValue = publicParameters.Modulus!.Length * 8;
        _cryptoClient = client;
        _publicParameters = publicParameters;
        _cancellationToken = cancellationToken;
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

        SignResult res = _cryptoClient.SignAsync(
            sigAlgo,
            hash,
            _cancellationToken).GetAwaiter().GetResult();
        return res.Signature;
    }
}
