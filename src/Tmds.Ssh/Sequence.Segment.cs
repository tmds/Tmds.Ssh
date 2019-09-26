// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;

namespace Tmds.Ssh
{
    partial class Sequence
    {
        internal sealed class Segment : ReadOnlySequenceSegment<byte>
        {
            private byte[]? _allocatedBuffer;
            internal int Start { get; private set; }
            internal int End { get; private set; }

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

            internal void Reset()
            {
                Memory = default;
                Next = null;
                RunningIndex = 0;
                _allocatedBuffer = null;
                Start = 0;
                End = 0;
            }

            internal void SetNext(Segment segment)
            {
                Next = segment;
                Next.RunningIndex = RunningIndex + End - Start;

                // We're no longer the last sequence, ReadOnlySequence no longer
                // delimits our length by End, so we must do it.
                Memory = AllocatedMemory.Slice(0, End);
            }

            internal void Advance(int count)
            {
                End += count;
            }

            internal void Remove(int count)
            {
                Start += count;
            }

            internal void UpdateRunningIndices()
            {
                RunningIndex = 0;
                long runningIndex = End - Start; // length of this segment.

                Segment? next = Next;
                while (next != null)
                {
                    next.RunningIndex = runningIndex;
                    runningIndex += next.End; // Only the first segment can have a non zero Start.
                    next = next.Next;
                }
            }
        }
    }
}