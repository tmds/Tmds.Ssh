// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;

namespace Tmds.Ssh;

// AES in counter mode as described in RFC 4344 for the aes[128|192|256]-ctr ciphers.
sealed class AesCtrCryptoTransform : IDisposableCryptoTransform
{
    internal const int AesBlockSize = 16;

    // Number of blocks for which the key stream is computed at once.
    private const int KeyStreamBlockCount = 4096 / AesBlockSize;

    private readonly Aes _aes;
    // The counter is treated as a big endian uint128 value that is incremented per block.
    private readonly byte[] _counter = new byte[AesBlockSize];
    private readonly byte[] _counterBlocks = new byte[KeyStreamBlockCount * AesBlockSize];
    private readonly byte[] _keyStream = new byte[KeyStreamBlockCount * AesBlockSize];

    public AesCtrCryptoTransform(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (iv.Length != AesBlockSize)
        {
            throw new ArgumentException(nameof(iv));
        }

        _aes = Aes.Create();
        _aes.Key = key.ToArray();
        iv.CopyTo(_counter);
    }

    // Encryption and decryption are the same operation for a stream cipher.
    public int BlockSize => AesBlockSize;

    public void Transform(ReadOnlySequence<byte> data, Sequence output)
    {
        if ((data.Length % AesBlockSize) != 0)
        {
            throw new ArgumentException(nameof(data));
        }

        while (!data.IsEmpty)
        {
            Span<byte> dst = output.AllocGetSpan(AesBlockSize);

            // Only transform whole blocks so the counter stays in sync with the block boundaries.
            int length = (int)Math.Min(data.Length, Math.Min(_keyStream.Length, dst.Length & ~(AesBlockSize - 1)));
            Debug.Assert(length >= AesBlockSize);

            dst = dst.Slice(0, length);
            data.Slice(0, length).CopyTo(dst);
            Xor(dst, GetKeyStream(length));

            output.AppendAlloced(length);
            data = data.Slice(length);
        }
    }

    private ReadOnlySpan<byte> GetKeyStream(int length)
    {
        Span<byte> counterBlocks = _counterBlocks.AsSpan(0, length);
        for (int offset = 0; offset < length; offset += AesBlockSize)
        {
            _counter.CopyTo(counterBlocks.Slice(offset, AesBlockSize));
            AesCtr.IncrementCounter(_counter);
        }

        // .NET does not have a CTR mode but we can use ECB with our own counter manipulation between blocks.
        int written = _aes.EncryptEcb(counterBlocks, _keyStream.AsSpan(0, length), PaddingMode.None);
        Debug.Assert(written == length);

        return _keyStream.AsSpan(0, length);
    }

    private static void Xor(Span<byte> dst, ReadOnlySpan<byte> src)
    {
        Debug.Assert(dst.Length == src.Length);

        int i = 0;
        if (Vector.IsHardwareAccelerated)
        {
            int vectorSize = Vector<byte>.Count;
            for (; i <= dst.Length - vectorSize; i += vectorSize)
            {
                Vector<byte> value = new Vector<byte>(dst.Slice(i)) ^ new Vector<byte>(src.Slice(i));
                value.CopyTo(dst.Slice(i));
            }
        }
        for (; i < dst.Length; i++)
        {
            dst[i] ^= src[i];
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_counter);
        CryptographicOperations.ZeroMemory(_keyStream);
        _aes.Dispose();
    }
}
