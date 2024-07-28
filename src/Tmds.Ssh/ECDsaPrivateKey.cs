// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
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

    public ECDsaPrivateKey(ECDsa ecdsa, Name algorithm, Name curveName, HashAlgorithmName hashAlgorithm) :
        base([algorithm])
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

    public override void AppendPublicKey(ref SequenceWriter writer)
    {
        ECParameters parameters = _ecdsa.ExportParameters(includePrivateParameters: false);

        using var innerData = writer.SequencePool.RentSequence();
        var innerWriter = new SequenceWriter(innerData);
        innerWriter.WriteString(_algorithm);
        innerWriter.WriteString(_curveName);
        innerWriter.WriteString(parameters.Q);

        writer.WriteString(innerData.AsReadOnlySequence());
    }

    public override void AppendSignature(Name algorithm, ref SequenceWriter writer, ReadOnlySequence<byte> data)
    {
        if (algorithm != _algorithm)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return;
        }

        byte[] signature = _ecdsa.SignData(
            data.IsSingleSegment ? data.FirstSpan : data.ToArray().AsSpan(),
            _hashAlgorithm,
            DSASignatureFormat.Rfc3279DerSequence);

        AsnReader reader = new AsnReader(signature, AsnEncodingRules.DER);
        AsnReader innerReader = reader.ReadSequence();
        BigInteger r = innerReader.ReadInteger();
        BigInteger s = innerReader.ReadInteger();

        using var ecdsaSigData = writer.SequencePool.RentSequence();
        var ecdsaSigWriter = new SequenceWriter(ecdsaSigData);
        ecdsaSigWriter.WriteMPInt(r);
        ecdsaSigWriter.WriteMPInt(s);

        using var innerData = writer.SequencePool.RentSequence();
        var innerWriter = new SequenceWriter(innerData);
        innerWriter.WriteString(algorithm);
        innerWriter.WriteString(ecdsaSigData.AsReadOnlySequence());

        writer.WriteString(innerData.AsReadOnlySequence());
    }
}
