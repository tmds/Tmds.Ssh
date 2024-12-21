// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Tmds.Ssh;

sealed class Ed25519PrivateKey : PrivateKey
{
    // Contains the private and public key as one block of bytes from the
    // serialized OpenSSH key data.
    private readonly byte[] _privateKey;
    private readonly byte[] _publicKey;

    public Ed25519PrivateKey(byte[] privateKey, byte[] publicKey, SshKey sshPublicKey) :
        base([AlgorithmNames.SshEd25519], sshPublicKey)
    {
        _privateKey = privateKey;
        _publicKey = publicKey;
    }

    public override void Dispose()
    { }

    public static SshKey DeterminePublicSshKey(byte[] privateKey, byte[] publicKey)
    {
        using var writer = new ArrayWriter();
        writer.WriteString(AlgorithmNames.SshEd25519);
        writer.WriteString(publicKey);

        return new SshKey(AlgorithmNames.SshEd25519, writer.ToArray());
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
            _privateKey,
            0,
            _publicKey,
            0,
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
