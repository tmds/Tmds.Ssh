// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Security.Cryptography;

namespace Tmds.Ssh;

static class Pbkdf1
{
    /// <summary>
    /// Modified version of PBKDF1 to derive a key for a PKCS#1 encrypted cipher.
    /// The modifications allow for deriving a key larger than the used hash length.
    /// </summary>
    public static byte[] DeriveKey(
        HashAlgorithmName hashName,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> salt,
        int rounds,
        int keySize)
    {
        using var hash = IncrementalHash.CreateHash(hashName);

        // Our initial output needs to be a multiple of the hash length.
        // The desired size is trimmed on return.
        int totalSize = (keySize + hash.HashLengthInBytes - 1) & ~(hash.HashLengthInBytes - 1);
        byte[] output = new byte[totalSize];

        // We may need to derive a key that is larger than the hash length.
        // This is a deviation from the PBKDF1 spec but is needed for PKCS#1
        // cipher keys. We repeat the process for the same amount of rounds
        // but start with the existing output data.
        int outWritten = 0;
        while (outWritten < output.Length)
        {
            ReadOnlySpan<byte> hashData = data;
            ReadOnlySpan<byte> saltData = salt;

            // First round should include the existing output data if any.
            if (outWritten > 0)
            {
                hash.AppendData(output.AsSpan(0, outWritten));
            }

            for (int i = 0; i < rounds; i++)
            {
                hash.AppendData(hashData);
                if (saltData.Length > 0)
                {
                    hash.AppendData(saltData);
                }

                hash.GetHashAndReset(output.AsSpan(outWritten));

                // Next rounds should use the hash as the data and no salt.
                hashData = output.AsSpan(outWritten, hash.HashLengthInBytes);
                saltData = Span<byte>.Empty;
            }

            outWritten += hash.HashLengthInBytes;
        }

        return output.AsSpan(0, keySize).ToArray();
    }
}
