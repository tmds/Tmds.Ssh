// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Security.Cryptography;

namespace Tmds.Ssh;

static class AesCtr
{
    public static byte[] DecryptCtr(ReadOnlySpan<byte> key, Span<byte> counter, ReadOnlySpan<byte> data)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();

        int blockSize = counter.Length;
        int offset = 0;
        Span<byte> temp = stackalloc byte[blockSize];

        byte[] decData = new byte[data.Length];
        while (offset < decData.Length)
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

            for (int i = 0; i < Math.Min(blockSize, decData.Length - offset); i++)
            {
                decData[i + offset] = (byte)(data[i + offset] ^ temp[i]);
            }

            offset += blockSize;
        }

        return decData;
    }
}
