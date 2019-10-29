// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;

namespace Tmds.Ssh
{
    sealed partial class Sequence : IDisposable
    {
#if DEBUG
        internal bool InPool;
#endif
        private Segment? _startSegment;
        private Segment? _endSegment;

        public SequencePool SequencePool { get; }

        public SequenceReader GetReader() => new SequenceReader(this);

        internal Sequence(SequencePool pool)
        {
            SequencePool = pool;
        }

        public long Length
        {
            get
            {
                if (_endSegment == null)
                {
                    return 0;
                }
                return (_endSegment.RunningIndex + _endSegment.End) - (_startSegment!.RunningIndex + _startSegment.Start);
            }
        }

        public bool IsEmpty
            => Length == 0;

        public Span<byte> FirstSpan
            => _startSegment == null ? default(Span<byte>) : _startSegment.Span;

        public void Clear()
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
        }

        internal ArraySegment<byte> AllocGetArraySegment(int sizeHint = 0)
        {
            // Quick check if there is sufficient space.
            int bytesAvailable = _endSegment?.BytesUnused ?? 0;
            if (bytesAvailable <= sizeHint)
            {
                AllocGetMemory(sizeHint);
            }

            return _endSegment!.UnusedArraySegment;
        }

        public void Dispose()
        {
            Clear();

            SequencePool.ReturnSequence(this);
        }

        private void ReturnSegment(Segment segment)
        {
            // Return Segment buffer
            byte[]? buffer = segment.AllocatedBuffer;
            if (buffer != null)
            {
                SequencePool.ReturnByteBuffer(buffer);
            }

            // Return Segment
            segment.Reset();
            SequencePool.ReturnSegment(segment);
        }

        public Memory<byte> AllocGetMemory(int sizeHint = 0)
        {
            if (sizeHint <= 0 || sizeHint > Constants.GuaranteedSizeHint)
            {
                sizeHint = Constants.GuaranteedSizeHint;
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
            _endSegment = SequencePool.RentSegment();
            _endSegment.SetBuffer(SequencePool.RentByteBuffer(sizeHint));
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
        {
            // Quick check if there is sufficient space.
            int bytesAvailable = _endSegment?.BytesUnused ?? 0;
            if (bytesAvailable <= sizeHint)
            {
                AllocGetMemory(sizeHint);
            }

            return _endSegment!.UnusedSpan;
        }

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

            if (_startSegment == null)
            {
                _endSegment = null;
            }
        }

        public void RemoveBack(long consumed)
        {
            while (consumed > 0)
            {
                Segment? endSegment = _endSegment;
                if (endSegment == null)
                {
                    ThrowHelper.ThrowArgumentOutOfRange(nameof(consumed));
                }

                int length = endSegment.End - endSegment.Start;
                if (length > consumed)
                {
                    endSegment.RemoveBack((int)consumed);
                    consumed = 0;
                }
                else
                {
                    _endSegment = endSegment.Previous;
                    _endSegment?.SetNext(null);

                    ReturnSegment(endSegment);

                    consumed -= length;
                }
            }

            if (_endSegment == null)
            {
                _startSegment = null;
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

        public SequenceReader<byte> CreateReader()
            => new SequenceReader<byte>(AsReadOnlySequence());

        public override string ToString()
            => PrettyBytePrinter.ToHexString(this);
    }
}