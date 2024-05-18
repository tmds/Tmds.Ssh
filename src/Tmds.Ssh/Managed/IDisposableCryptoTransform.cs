// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;

namespace Tmds.Ssh.Managed;

interface IDisposableCryptoTransform : IDisposable
{
    // Input length must be a multiple.
    int BlockSize { get; }
    void Transform(ReadOnlySequence<byte> data, Sequence output);
}
