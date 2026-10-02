// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

interface ICompressor : IDisposable
{
    void Compress(ReadOnlySequence<byte> payload, Sequence destination);
}
