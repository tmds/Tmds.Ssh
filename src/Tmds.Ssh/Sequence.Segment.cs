// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

partial class Sequence
{
    internal sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        private byte[]? _allocatedBuffer;
        internal int Start { get; private set; }
        internal int End { get; private set; }
        public Segment? Previous { get; private set; }

        internal void SetBuffer(byte[] buffer)
        {
            _allocatedBuffer = buffer;

            // note: ReadOnlySegment delimits our buffer by Start, End.
            Memory = buffer;
        }

        internal byte[]? AllocatedBuffer { get => _allocatedBuffer; }
        internal Memory<byte> AllocatedMemory => AllocatedBuffer;
        internal Memory<byte> Unused => AllocatedMemory.Slice(End);
        internal Span<byte> UnusedSpan
        {
            get => new Span<byte>(_allocatedBuffer, End, BytesUnused);
        }

        internal int BytesUnused
            => AllocatedBuffer!.Length - End;

        internal new Segment? Next
        {
            get => (Segment?)base.Next;
            private set => base.Next = value;
        }

        public ArraySegment<byte> UnusedArraySegment
        {
            get => new ArraySegment<byte>(_allocatedBuffer!, End, BytesUnused);
        }

        public Span<byte> Span
            => _allocatedBuffer.AsSpan(Start, End - Start);

        internal void Reset()
        {
            Memory = default;
            Next = null;
            RunningIndex = 0;
            _allocatedBuffer = null;
            Start = 0;
            End = 0;
            Previous = null;
        }

        internal void SetNext(Segment? segment)
        {
            Next = segment;

            if (segment != null)
            {
                segment.RunningIndex = RunningIndex + End;
                segment.Previous = this;

                // We're no longer the last sequence, ReadOnlySequence no longer
                // delimits our length by End, so we must do it.
                Memory = AllocatedMemory.Slice(0, End);
            }
            else
            {
                Memory = AllocatedMemory;
            }
        }

        internal void Advance(int count)
        {
            End += count;
        }

        internal void Remove(int count)
        {
            Start += count;
        }

        internal void RemoveBack(int count)
        {
            End -= count;
        }
    }
}
