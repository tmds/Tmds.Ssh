// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Tmds.Ssh;

class MlDsa44Ed25519PublicKey : PublicKeyAlgorithm
{
    private const int Ed25519PublicKeySize = 32;
    internal const int CompositePublicKeySize = MlDsaKey.MlDsa44PublicKeySize + Ed25519PublicKeySize;

    private const int Ed25519SignatureSize = 64;
    internal const int CompositeSignatureSize = MlDsaKey.MlDsa44SignatureSize + Ed25519SignatureSize;

    private readonly byte[] _mlDsaPublicKey;
    private readonly byte[] _ed25519PublicKey;

    public MlDsa44Ed25519PublicKey(byte[] mlDsaPublicKey, byte[] ed25519PublicKey)
    {
        _mlDsaPublicKey = mlDsaPublicKey;
        _ed25519PublicKey = ed25519PublicKey;
    }

    public static SshKeyData DeterminePublicSshKey(byte[] mlDsaPublicKey, byte[] ed25519PublicKey)
    {
        using var writer = new ArrayWriter();
        writer.WriteString(AlgorithmNames.SshMlDsa44Ed25519);
        byte[] combined = new byte[CompositePublicKeySize];
        mlDsaPublicKey.CopyTo(combined, 0);
        ed25519PublicKey.CopyTo(combined, MlDsaKey.MlDsa44PublicKeySize);
        writer.WriteString(combined);
        return new SshKeyData(AlgorithmNames.SshMlDsa44Ed25519, writer.ToArray());
    }

    public static MlDsa44Ed25519PublicKey CreateFromSshKey(ReadOnlyMemory<byte> key)
    {
        SequenceReader reader = new SequenceReader(key);
        reader.ReadName(AlgorithmNames.SshMlDsa44Ed25519);
        ReadOnlySequence<byte> pkBlob = reader.ReadStringAsBytes();
        if (pkBlob.Length != CompositePublicKeySize)
        {
            ThrowHelper.ThrowDataUnexpectedValue();
        }

        byte[] combined = pkBlob.ToArray();
        byte[] mlDsaPk = combined.AsSpan(0, MlDsaKey.MlDsa44PublicKeySize).ToArray();
        byte[] ed25519Pk = combined.AsSpan(MlDsaKey.MlDsa44PublicKeySize, Ed25519PublicKeySize).ToArray();
        return new MlDsa44Ed25519PublicKey(mlDsaPk, ed25519Pk);
    }

    internal override bool VerifySignature(Name algorithmName, ReadOnlySpan<byte> data, ReadOnlySequence<byte> signature)
    {
        if (algorithmName != AlgorithmNames.SshMlDsa44Ed25519)
        {
            ThrowHelper.ThrowDataUnexpectedValue();
        }

        if (signature.Length != CompositeSignatureSize)
        {
            ThrowHelper.ThrowDataUnexpectedValue();
        }

        byte[] sigBytes = signature.ToArray();
        byte[] mPrime = MlDsa44Ed25519Crypto.ConstructMPrime(data);

        using MlDsaKey mlDsa = MlDsaKey.ImportPublicKey(_mlDsaPublicKey);
        if (!mlDsa.VerifyData(mPrime, sigBytes.AsSpan(0, MlDsaKey.MlDsa44SignatureSize),
            MlDsa44Ed25519Crypto.CompositeLabel))
        {
            return false;
        }

        return Ed25519.Verify(sigBytes, MlDsaKey.MlDsa44SignatureSize, _ed25519PublicKey, 0, mPrime, 0, mPrime.Length);
    }
}
