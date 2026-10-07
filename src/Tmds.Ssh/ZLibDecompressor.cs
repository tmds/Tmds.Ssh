// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics;
using System.IO.Compression;

namespace Tmds.Ssh;

sealed class ZLibDecompressor : IDecompressor
{
#if NET11_0_OR_GREATER
    private readonly ZLibDecoder _decoder;

    public ZLibDecompressor()
    {
        _decoder = new ZLibDecoder();
    }

    public void Decompress(ReadOnlySequence<byte> payload, Sequence destination, int maxLength)
    {
        long decompressedLength = 0;

        foreach (ReadOnlyMemory<byte> segment in payload)
        {
            ReadOnlySpan<byte> source = segment.Span;
            OperationStatus status;
            do
            {
                // AllocGetSpan(1) fills existing segments before allocating new ones.
                // This is required because the Packet header occupies the start of the first segment
                // and Packet.MessageId reads from FirstSpan.
                Span<byte> dest = destination.AllocGetSpan(1);
                status = _decoder.Decompress(source, dest, out int consumed, out int written);
                AssertStatus(status, written, dest.Length, consumed, source.Length);
                destination.AppendAlloced(written);
                source = source.Slice(consumed);

                decompressedLength += written;
                if (decompressedLength > maxLength)
                {
                    ThrowHelper.ThrowProtocolPacketTooLong();
                }

                // Done (StreamEnd) should not occur in SSH — the zlib stream is never finalized.
                if (status == OperationStatus.InvalidData || status == OperationStatus.Done)
                {
                    ThrowHelper.ThrowProtocolDecompressionError("Invalid data.");
                }
            } while (status == OperationStatus.DestinationTooSmall);
        }
    }

    public void Dispose()
    {
        _decoder.Dispose();
    }

    [Conditional("DEBUG")]
    private static void AssertStatus(OperationStatus status, int written, int destLength, int consumed, int sourceLength)
    {
        // We assume zlib will fill the entire destination before reporting DestinationTooSmall.
        Debug.Assert(status is not OperationStatus.DestinationTooSmall || written == destLength);

        // We assume zlib will consume the entire source before reporting NeedMoreData.
        Debug.Assert(status is not OperationStatus.NeedMoreData || consumed == sourceLength);
    }
#else
    // When this .NET switch is enabled, ZLibStream requires each block to be terminated with a zlib end marker.
    // SSH compression sync-flushes without ending, so ZLibStream throws InvalidDataException at each packet boundary.
    // This doesn't affect the default (switch off) where Read returns 0.
    private static readonly bool s_useStrictValidation =
        AppContext.TryGetSwitch("System.IO.Compression.UseStrictValidation", out bool strictValidation) && strictValidation;

    private readonly SourceStream _source;
    private readonly ZLibStream _inflater;

    public ZLibDecompressor()
    {
        _source = new SourceStream();
        _inflater = new ZLibStream(_source, CompressionMode.Decompress, leaveOpen: true);
    }

    // Appends the decompressed form of 'payload' to 'destination'.
    // 'maxLength' bounds the decompressed length so a peer can not force us to allocate an arbitrary amount of memory.
    public void Decompress(ReadOnlySequence<byte> payload, Sequence destination, int maxLength)
    {
        _source.Data = payload;
        try
        {
            long decompressedLength = 0;
            while (true)
            {
                // AllocGetSpan(1) fills existing segments before allocating new ones.
                // This is required because the Packet header occupies the start of the first segment
                // and Packet.MessageId reads from FirstSpan.
                Span<byte> span = destination.AllocGetSpan(1);
                int bytesRead = 0;
                try
                {
                    bytesRead = _inflater.Read(span);
                }
                catch (InvalidDataException) when (s_useStrictValidation && decompressedLength > 0)
                {
                    break;
                }
                catch (InvalidDataException e)
                {
                    ThrowHelper.ThrowProtocolDecompressionError(e.Message, e);
                }

                if (bytesRead == 0)
                {
                    break;
                }

                destination.AppendAlloced(bytesRead);

                decompressedLength += bytesRead;
                if (decompressedLength > maxLength)
                {
                    ThrowHelper.ThrowProtocolPacketTooLong();
                }
            }
        }
        finally
        {
            _source.Data = default;
        }
    }

    public void Dispose()
    {
        _inflater.Dispose();
        _source.Dispose();
    }

    // Reads from a Sequence. Returns zero when all of it was read.
    private sealed class SourceStream : Stream
    {
        public ReadOnlySequence<byte> Data { get; set; }

        public override int Read(Span<byte> buffer)
        {
            int length = (int)Math.Min(buffer.Length, Data.Length);
            if (length == 0)
            {
                return 0;
            }

            Data.Slice(0, length).CopyTo(buffer.Slice(0, length));
            Data = Data.Slice(length);

            return length;
        }

        public override int Read(byte[] buffer, int offset, int count)
            => Read(buffer.AsSpan(offset, count));

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
#endif
}
