// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class RsaPrivateKey : PrivateKey
{
    private readonly RSA _rsa;

    public RsaPrivateKey(RSA rsa, SshKeyData sshPublicKey) :
        base(AlgorithmNames.SshRsaAlgorithms, sshPublicKey)
    {
        _rsa = rsa ?? throw new ArgumentNullException(nameof(rsa));
    }

    public int KeySize => _rsa.KeySize;

    public override void Dispose()
    {
        _rsa.Dispose();
    }

    public static SshKeyData DeterminePublicSshKey(RSA rsa)
    {
        RSAParameters parameters = rsa.ExportParameters(includePrivateParameters: false);

        return RsaPublicKey.DeterminePublicSshKey(parameters.Exponent!, parameters.Modulus!);
    }

    public override ValueTask<byte[]> SignAsync(Name algorithm, byte[] data, CancellationToken cancellationToken)
    {
        HashAlgorithmName hashAlgorithmName;
        if (algorithm == AlgorithmNames.RsaSshSha2_256)
        {
            hashAlgorithmName = HashAlgorithmName.SHA256;
        }
        else if (algorithm == AlgorithmNames.RsaSshSha2_512)
        {
            hashAlgorithmName = HashAlgorithmName.SHA512;
        }
        else
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return default;
        }
        var innerWriter = new ArrayWriter();
        innerWriter.WriteString(algorithm);
        int signatureLength = _rsa.KeySize / 8;
        byte[] signature = new byte[signatureLength];
        if (!_rsa.TrySignData(data, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, out int bytesWritten) ||
            bytesWritten != signatureLength)
        {
            throw new InvalidOperationException("Unable to sign data.");
        }
        innerWriter.WriteString(signature);

        return ValueTask.FromResult(innerWriter.ToArray());
    }
}
