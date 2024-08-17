// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Tmds.Ssh;

sealed class Ed25519PrivateKey : PrivateKey
{
    private const int _privateKeySize = 32;

    // Contains the private and public key as one block of bytes from the
    // serialized OpenSSH key data.
    private readonly byte[] _keyData;

    public Ed25519PrivateKey(byte[] keyData) :
        base([AlgorithmNames.SshEd25519])
    {
        _keyData = keyData;
    }

    public override void Dispose()
    { }

    public override void AppendPublicKey(ref SequenceWriter writer)
    {
        using var innerData = writer.SequencePool.RentSequence();
        var innerWriter = new SequenceWriter(innerData);
        innerWriter.WriteString(Algorithms[0]);
        innerWriter.WriteString(_keyData.AsSpan(_privateKeySize));

        writer.WriteString(innerData.AsReadOnlySequence());
    }

    public override void AppendSignature(Name algorithm, ref SequenceWriter writer, ReadOnlySequence<byte> data)
    {
        if (algorithm != Algorithms[0])
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return;
        }

        byte[] signature = new byte[Ed25519.SignatureSize];
        Ed25519.Sign(
            // private key
            _keyData,
            0,
            // public key
            _keyData,
            _privateKeySize,
            data.ToArray(),
            0,
            (int)data.Length,
            signature,
            0);

        using var innerData = writer.SequencePool.RentSequence();
        var innerWriter = new SequenceWriter(innerData);
        innerWriter.WriteString(algorithm);
        innerWriter.WriteString(signature);

        writer.WriteString(innerData.AsReadOnlySequence());
    }
}
