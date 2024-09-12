// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

static class AesCtr
{
    public static void DecryptCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        Span<byte> counter = stackalloc byte[iv.Length];
        iv.CopyTo(counter);

        if (plaintext.Length < ciphertext.Length)
        {
            throw new ArgumentException("Plaintext buffer is too small.");
        }

        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();

        int blockSize = counter.Length;
        int offset = 0;
        Span<byte> temp = stackalloc byte[blockSize];

        while (offset < ciphertext.Length)
        {
            // .NET Does not have a CTR mode but we can use ECB with out own
            // iv/counter manipulation between blocks.
            aes.EncryptEcb(counter, temp, PaddingMode.None);

            // Increment the counter that is treated as a big endian uint128
            // value.
            for (int i = blockSize - 1; i >= 0; i--)
            {
                if (++counter[i] != 0)
                {
                    break;
                }
            }

            for (int i = 0; i < Math.Min(blockSize, ciphertext.Length - offset); i++)
            {
                plaintext[i + offset] = (byte)(ciphertext[i + offset] ^ temp[i]);
            }

            offset += blockSize;
        }
    }
}
