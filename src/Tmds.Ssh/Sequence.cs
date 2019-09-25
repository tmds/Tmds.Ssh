// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;

namespace Tmds.Ssh
{
    sealed partial class Sequence : IDisposable, IBufferWriter<byte>
    {
        private Segment? _startSegment;
        private Segment? _endSegment;
        private readonly SequencePool _pool;

        internal Sequence(SequencePool pool)
        {
            _pool = pool;
        }

        public void Dispose()
        {
            var segment = _startSegment;
            while (segment != null)
            {
                var next = segment.Next;

                ReturnSegment(segment);

                segment = next;
            }

            // Return Sequence
            _startSegment = null;
            _endSegment = null;
            _pool.ReturnSequence(this);
        }

        private void ReturnSegment(Segment segment)
        {
            // Return Segment buffer
            byte[]? buffer = segment.AllocatedBuffer;
            if (buffer != null)
            {
                _pool.ReturnByteBuffer(buffer);
            }

            // Return Segment
            segment.Reset();
            _pool.ReturnSegment(segment);
        }

        public Memory<byte> AllocGetMemory(int sizeHint = 0)
        {
            if (sizeHint < 0)
            {
                ThrowHelper.ThrowArgumentOutOfRange(nameof(sizeHint));
            }
            else if (sizeHint == 0 || sizeHint > 1024)
            {
                sizeHint = 1024;
            }

            int bytesAvailable = _endSegment?.BytesUnused ?? 0;
            if (bytesAvailable < sizeHint)
            {
                AddSegment(sizeHint);
            }

            return _endSegment!.Unused;
        }

        private void AddSegment(int sizeHint)
        {
            Segment? previousEnd = _endSegment;
            _endSegment = _pool.RentSegment();
            _endSegment.SetBuffer(_pool.RentByteBuffer(sizeHint));
            if (_startSegment == null)
            {
                _startSegment = _endSegment;
            }
            else
            {
                previousEnd!.SetNext(_endSegment);
            }
        }

        public Span<byte> AllocGetSpan(int sizeHint = 0)
            => AllocGetMemory(sizeHint).Span;

        public void AppendAlloced(int length)
        {
            if ((uint)length > (uint)(_endSegment?.BytesUnused ?? 0))
            {
                ThrowHelper.ThrowArgumentOutOfRange(nameof(length));
            }

            _endSegment!.Advance(length);
        }

        public void Remove(long consumed)
        {
            while (consumed > 0)
            {
                Segment? startSegment = _startSegment;
                if (startSegment == null)
                {
                    ThrowHelper.ThrowArgumentOutOfRange(nameof(consumed));
                }

                int length = startSegment.End - startSegment.Start;
                if (length > consumed)
                {
                    startSegment.Remove((int)consumed);
                    consumed = 0;
                }
                else
                {
                    _startSegment = startSegment.Next;

                    ReturnSegment(startSegment);

                    consumed -= length;
                }
            }

            if (_startSegment != null)
            {
                _startSegment.UpdateRunningIndices();
            }
            else
            {
                _endSegment = null;
            }
        }

        public ReadOnlySequence<byte> AsReadOnlySequence()
        {
            if (_startSegment == null)
            {
                return ReadOnlySequence<byte>.Empty;
            }
            else
            {
                return new ReadOnlySequence<byte>(_startSegment, _startSegment.Start, _endSegment!, _endSegment!.End);
            }
        }

        void IBufferWriter<byte>.Advance(int count)
            => AppendAlloced(count);

        Memory<byte> IBufferWriter<byte>.GetMemory(int sizeHint)
            => AllocGetMemory(sizeHint);

        Span<byte> IBufferWriter<byte>.GetSpan(int sizeHint)
            => AllocGetSpan(sizeHint);
    }
}