// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Tmds.Ssh;

class Ed25519PublicKey : PublicKey
{
    private readonly byte[] _publicKey;

    public Ed25519PublicKey(byte[] publicKey)
    {
        _publicKey = publicKey;
    }

    public static SshKey DeterminePublicSshKey(byte[] publicKey)
    {
        using var writer = new ArrayWriter();
        writer.WriteString(AlgorithmNames.SshEd25519);
        writer.WriteString(publicKey);
        return new SshKey(AlgorithmNames.SshEd25519, writer.ToArray());
    }

    public static Ed25519PublicKey CreateFromSshKey(ReadOnlyMemory<byte> key)
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

    internal override bool VerifySignature(Name algorithmName, ReadOnlySpan<byte> data, ReadOnlySequence<byte> signature)
    {
        if (algorithmName != AlgorithmNames.SshEd25519)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }

        if (signature.Length != Ed25519.SignatureSize)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }

        return Ed25519.Verify(signature.ToArray(), 0, _publicKey, 0, data.ToArray(), 0, data.Length);
    }
}
