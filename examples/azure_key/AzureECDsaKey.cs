using Azure.Security.KeyVault.Keys.Cryptography;
using System;
using System.Security.Cryptography;
using System.Threading;
using AzureSignatureAlgorithm = Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm;

namespace Tmds.Ssh.AzureKeyExample;

sealed class AzureECDsaKey : ECDsa
{
    private readonly CryptographyClient _cryptoClient;
    private readonly ECParameters _publicParameters;
    private readonly AzureSignatureAlgorithm _signatureAlgorithm;
    private readonly CancellationToken _cancellationToken;

    public AzureECDsaKey(
        CryptographyClient client,
        ECParameters publicParameters,
        AzureSignatureAlgorithm signatureAlgorithm,
        CancellationToken cancellationToken)
    {
        KeySizeValue = publicParameters.Q.X!.Length * 8;
        _cryptoClient = client;
        _publicParameters = publicParameters;
        _signatureAlgorithm = signatureAlgorithm;
        _cancellationToken = cancellationToken;
    }

    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException("Cannot export private parameters");
        }

        return _publicParameters;
    }

    public override byte[] SignHash(byte[] hash)
        => _cryptoClient.SignAsync(
            _signatureAlgorithm,
            hash,
            _cancellationToken).GetAwaiter().GetResult().Signature;

    public override bool VerifyHash(byte[] hash, byte[] signature)
        => throw new NotImplementedException();
}
