// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Tmds.Ssh;

class Ed25519PublicKey : PublicKey
{
    private readonly byte[] _publicKey;

    private Ed25519PublicKey(byte[] publicKey)
    {
        _publicKey = publicKey;
    }

    public static Ed25519PublicKey CreateFromSshKey(byte[] key)
    {
        SequenceReader reader = new SequenceReader(key);
        reader.ReadName(AlgorithmNames.SshEd25519);
        ReadOnlySequence<byte> publicKey = reader.ReadStringAsBytes();
        if (publicKey.Length != Ed25519.PublicKeySize)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }
        return new Ed25519PublicKey(publicKey.ToArray());
    }

    internal override bool VerifySignature(IReadOnlyList<Name> allowedAlgorithms, Span<byte> data, ReadOnlySequence<byte> signature)
    {
        var reader = new SequenceReader(signature);
        reader.ReadName(AlgorithmNames.SshEd25519, allowedAlgorithms);
        ReadOnlySequence<byte> signatureSequence = reader.ReadStringAsBytes();
        if (signatureSequence.Length != Ed25519.SignatureSize)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }

        return Ed25519.Verify(signatureSequence.ToArray(), 0, _publicKey, 0, data.ToArray(), 0, data.Length);
    }
}
