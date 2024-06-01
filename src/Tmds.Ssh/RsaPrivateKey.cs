// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class RsaPrivateKey : PrivateKey
{
    private readonly RSA _rsa;

    public RsaPrivateKey(RSA rsa) :
        base(AlgorithmNames.SshRsaAlgorithms)
    {
        _rsa = rsa ?? throw new ArgumentNullException(nameof(rsa));
    }

    public override void Dispose()
    {
        _rsa.Dispose();
    }

    public override void AppendPublicKey(ref SequenceWriter writer)
    {
        RSAParameters parameters = _rsa.ExportParameters(includePrivateParameters: false);
        using var innerData = writer.SequencePool.RentSequence();
        var innerWriter = new SequenceWriter(innerData);
        innerWriter.WriteString(AlgorithmNames.SshRsa);
        innerWriter.WriteMPInt(parameters.Exponent);
        innerWriter.WriteMPInt(parameters.Modulus);

        writer.WriteString(innerData.AsReadOnlySequence());
    }

    public override void AppendSignature(Name algorithm, ref SequenceWriter writer, ReadOnlySequence<byte> data)
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
            return;
        }
        using var innerData = writer.SequencePool.RentSequence();
        var innerWriter = new SequenceWriter(innerData);
        innerWriter.WriteString(algorithm);
        int signatureLength = _rsa.KeySize / 8;
        byte[] signature = new byte[signatureLength];
        if (!_rsa.TrySignData(data.ToArray(), signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, out int bytesWritten) ||
            bytesWritten != signatureLength)
        {
            throw new InvalidOperationException("Unable to sign data.");
        }
        innerWriter.WriteString(signature);

        writer.WriteString(innerData.AsReadOnlySequence());
    }
}
