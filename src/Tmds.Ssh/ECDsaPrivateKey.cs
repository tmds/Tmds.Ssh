// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class ECDsaPrivateKey : PrivateKey
{
    private readonly ECDsa _ecdsa;
    private readonly Name _algorithm;
    private readonly Name _curveName;
    private readonly HashAlgorithmName _hashAlgorithm;

    public ECDsaPrivateKey(ECDsa ecdsa, Name algorithm, Name curveName, HashAlgorithmName hashAlgorithm, SshKey sshPublicKey) :
        base([algorithm], sshPublicKey)
    {
        _ecdsa = ecdsa ?? throw new ArgumentNullException(nameof(ecdsa));
        _algorithm = algorithm;
        _curveName = curveName;
        _hashAlgorithm = hashAlgorithm;
    }

    public override void Dispose()
    {
        _ecdsa.Dispose();
    }

    public static SshKey DeterminePublicSshKey(ECDsa ecdsa, Name algorithm, Name curveName)
    {
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);

        using var writer = new ArrayWriter();
        writer.WriteString(algorithm);
        writer.WriteString(curveName);
        writer.WriteString(parameters.Q);

        return new SshKey(algorithm, writer.ToArray());
    }

    public override ValueTask<byte[]?> TrySignAsync(Name algorithm, byte[] data, CancellationToken cancellationToken)
    {
        if (algorithm != _algorithm)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return default;
        }

        byte[] signature = _ecdsa.SignData(
            data,
            _hashAlgorithm,
            DSASignatureFormat.Rfc3279DerSequence);

        AsnReader reader = new AsnReader(signature, AsnEncodingRules.DER);
        AsnReader innerReader = reader.ReadSequence();
        BigInteger r = innerReader.ReadInteger();
        BigInteger s = innerReader.ReadInteger();

        var ecdsaSigWriter = new ArrayWriter();
        ecdsaSigWriter.WriteMPInt(r);
        ecdsaSigWriter.WriteMPInt(s);

        var innerWriter = new ArrayWriter();
        innerWriter.WriteString(algorithm);
        innerWriter.WriteString(ecdsaSigWriter.ToArray());

        return ValueTask.FromResult((byte[]?)innerWriter.ToArray());
    }
}
