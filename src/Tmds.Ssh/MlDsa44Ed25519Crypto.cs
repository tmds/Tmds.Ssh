// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

// draft-miller-sshm-mldsa44-ed25519-composite-sigs-00
// based on draft-ietf-lamps-pq-composite-sigs-18
static class MlDsa44Ed25519Crypto
{
    private static readonly byte[] CompositePrefix = "CompositeAlgorithmSignatures2025"u8.ToArray();
    internal static readonly byte[] CompositeLabel = "COMPSIG-MLDSA44-Ed25519-SHA512"u8.ToArray();

    internal static byte[] ConstructMPrime(ReadOnlySpan<byte> message)
    {
        return ConstructMPrime(message, ReadOnlySpan<byte>.Empty);
    }

    internal static byte[] ConstructMPrime(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context)
    {
        byte[] hash = SHA512.HashData(message);

        int length = CompositePrefix.Length + CompositeLabel.Length + 1 + context.Length + hash.Length;
        byte[] mPrime = new byte[length];
        int offset = 0;

        CompositePrefix.CopyTo(mPrime.AsSpan(offset));
        offset += CompositePrefix.Length;

        CompositeLabel.CopyTo(mPrime.AsSpan(offset));
        offset += CompositeLabel.Length;

        mPrime[offset++] = (byte)context.Length;

        context.CopyTo(mPrime.AsSpan(offset));
        offset += context.Length;

        hash.CopyTo(mPrime.AsSpan(offset));

        return mPrime;
    }
}
