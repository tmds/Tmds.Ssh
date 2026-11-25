// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Tmds.Ssh;

sealed class MlDsa44Ed25519PrivateKey : PrivateKey
{
    private readonly byte[] _mlDsaSeed;
    private readonly byte[] _ed25519PrivateKey;
    private readonly byte[] _ed25519PublicKey;

    public MlDsa44Ed25519PrivateKey(byte[] mlDsaSeed, byte[] ed25519PrivateKey, byte[] ed25519PublicKey, SshKeyData sshPublicKey) :
        base(AlgorithmNames.SshMlDsa44Ed25519Algorithms, sshPublicKey)
    {
        _mlDsaSeed = mlDsaSeed;
        _ed25519PrivateKey = ed25519PrivateKey;
        _ed25519PublicKey = ed25519PublicKey;
    }

    public override void Dispose()
    { }

    public override ValueTask<byte[]> SignAsync(Name algorithm, byte[] data, CancellationToken cancellationToken)
    {
        if (algorithm != Algorithms[0])
        {
            ThrowHelper.ThrowDataUnexpectedValue();
            return default;
        }

        byte[] mPrime = MlDsa44Ed25519Crypto.ConstructMPrime(data);

        using MlDsaKey mlDsa = MlDsaKey.ImportPrivateSeed(_mlDsaSeed);
        byte[] mlDsaSig = mlDsa.SignData(mPrime, MlDsa44Ed25519Crypto.CompositeLabel);

        byte[] ed25519Sig = new byte[Ed25519.SignatureSize];
        Ed25519.Sign(
            _ed25519PrivateKey, 0,
            _ed25519PublicKey, 0,
            mPrime, 0, mPrime.Length,
            ed25519Sig, 0);

        byte[] compositeSig = new byte[mlDsaSig.Length + ed25519Sig.Length];
        mlDsaSig.CopyTo(compositeSig, 0);
        ed25519Sig.CopyTo(compositeSig, mlDsaSig.Length);

        var innerWriter = new ArrayWriter();
        innerWriter.WriteString(algorithm);
        innerWriter.WriteString(compositeSig);

        return ValueTask.FromResult(innerWriter.ToArray());
    }
}
