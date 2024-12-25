// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Tmds.Ssh;

sealed class Ed25519PrivateKey : PrivateKey
{
    // Contains the private and public key as one block of bytes from the
    // serialized OpenSSH key data.
    private readonly byte[] _privateKey;
    private readonly byte[] _publicKey;

    public Ed25519PrivateKey(byte[] privateKey, byte[] publicKey, SshKey sshPublicKey) :
        base(AlgorithmNames.SshEd25519Algorithms, sshPublicKey)
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

    public override ValueTask<byte[]> SignAsync(Name algorithm, byte[] data, CancellationToken cancellationToken)
    {
        if (algorithm != Algorithms[0])
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return default;
        }

        byte[] signature = new byte[Ed25519.SignatureSize];
        Ed25519.Sign(
            _privateKey,
            0,
            _publicKey,
            0,
            data,
            0,
            (int)data.Length,
            signature,
            0);

        var innerWriter = new ArrayWriter();
        innerWriter.WriteString(algorithm);
        innerWriter.WriteString(signature);

        return ValueTask.FromResult(innerWriter.ToArray());
    }
}
