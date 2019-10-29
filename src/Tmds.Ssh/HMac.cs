// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Tmds.Ssh
{
    sealed class HMac : IHMac
    {
        public static IHMac None = new HMacNone();

        private readonly IncrementalHash _incrementalHash;

        private readonly byte[] _hash;

        public int HashSize { get; }

        public HMac(HashAlgorithmName algorithmName, int nativeHashSize, int hashSize, byte[] key)
        {
            _incrementalHash = IncrementalHash.CreateHMAC(algorithmName, key);
            HashSize = hashSize;
            _hash = new byte[nativeHashSize];
        }

        public int BlockSize => 1;

        public void Dispose()
        {
            _incrementalHash.Dispose();
        }

        public void Transform(Span<byte> prefix, ReadOnlySequence<byte> data, Span<byte> suffix, Sequence output)
        {
            _incrementalHash.AppendData(prefix);
            foreach (var segment in data)
            {
                _incrementalHash.AppendData(segment.Span);
            }
            _incrementalHash.AppendData(suffix);

            bool hashed = _incrementalHash.TryGetHashAndReset(_hash.AsSpan(), out int bytesWritten);
            Debug.Assert(hashed);
            Debug.Assert(bytesWritten == _hash.Length);

            Span<byte> hash = _hash.AsSpan().Slice(0, HashSize);
            hash.CopyTo(output.AllocGetSpan(HashSize));
            output.AppendAlloced(HashSize);
        }

        sealed private class HMacNone : IHMac
        {
            public int BlockSize => 1;

            public int HashSize => 0;

            public void Dispose()
            { }

            public void Transform(Span<byte> prefix, ReadOnlySequence<byte> data, Span<byte> suffix, Sequence output)
            { }
        }
    }
}