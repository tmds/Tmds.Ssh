// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.IO.Compression;

namespace Tmds.Ssh;

sealed class ZLibCompressor : ICompressor
{
    private readonly DestinationStream _destination;
    private readonly ZLibStream _deflater;

    public ZLibCompressor()
    {
        _destination = new DestinationStream();
        // CompressionLevel.Optimal is zlib level 6, which is the level used by OpenSSH.
        _deflater = new ZLibStream(_destination, CompressionLevel.Optimal, leaveOpen: true);
    }

    public void Compress(ReadOnlySequence<byte> payload, Sequence destination)
    {
        _destination.Sequence = destination;
        try
        {
            foreach (ReadOnlyMemory<byte> segment in payload)
            {
                _deflater.Write(segment.Span);
            }

            _deflater.Flush();
        }
        finally
        {
            _destination.Sequence = null;
        }
    }

    public void Dispose()
    {
        _deflater.Dispose();
        _destination.Dispose();
    }

    private sealed class DestinationStream : Stream
    {
        public Sequence? Sequence { get; set; }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (Sequence is Sequence sequence)
            {
                buffer.CopyTo(sequence.AllocGetSpan(buffer.Length));
                sequence.AppendAlloced(buffer.Length);
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
            => Write(buffer.AsSpan(offset, count));

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
