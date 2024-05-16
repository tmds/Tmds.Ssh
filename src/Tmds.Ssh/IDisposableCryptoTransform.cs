// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;

namespace Tmds.Ssh
{
    interface IDisposableCryptoTransform : IDisposable
    {
        // Input length must be a multiple.
        int BlockSize { get; }
        // Transforms [prefix, data, suffix] and appends it to output.
        void Transform(Span<byte> prefix, ReadOnlySequence<byte> data, Span<byte> suffix, Sequence output);
    }
}