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
    private readonly Name _ecIdentifier;
    private readonly Name _curveName;
    private readonly HashAlgorithmName _allowedAlgorithm;

    public ECDsaPrivateKey(ECDsa ecdsa, Name identifier, Name curveName, HashAlgorithmName allowedAlgorithm) :
        base([identifier])
    {
        _ecdsa = ecdsa ?? throw new ArgumentNullException(nameof(ecdsa));
        _ecIdentifier = identifier;
        _curveName = curveName;
        _allowedAlgorithm = allowedAlgorithm;
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
        innerWriter.WriteString(_ecIdentifier);
        innerWriter.WriteString(_curveName);
        innerWriter.WriteString(parameters.Q);

        writer.WriteString(innerData.AsReadOnlySequence());
    }

    public override void AppendSignature(Name algorithm, ref SequenceWriter writer, ReadOnlySequence<byte> data)
    {
        if (algorithm != _ecIdentifier)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return;
        }

        byte[] signature = _ecdsa.SignData(
            data.IsSingleSegment ? data.FirstSpan : data.ToArray().AsSpan(),
            _allowedAlgorithm,
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
