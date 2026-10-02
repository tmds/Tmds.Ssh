// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

interface IDecompressor : IDisposable
{
    void Decompress(ReadOnlySequence<byte> payload, Sequence destination, int maxLength);
}
