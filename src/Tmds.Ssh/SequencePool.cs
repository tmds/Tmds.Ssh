// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace Tmds.Ssh
{
    sealed class SequencePool
    {
        private readonly ConcurrentBag<Sequence> _sequenceBag = new ConcurrentBag<Sequence>();
        private readonly ConcurrentBag<Sequence.Segment> _segmentBag = new ConcurrentBag<Sequence.Segment>();

        public Sequence RentSequence()
        {
            if (_sequenceBag.TryTake(out Sequence? sequence))
            {
#if DEBUG
                Debug.Assert(sequence.InPool);
                sequence.InPool = false;
#endif
                return sequence!;
            }
            else
            {
                return new Sequence(this);
            }
        }

        internal void ReturnSequence(Sequence sequence)
        {
#if DEBUG
            Debug.Assert(!sequence!.InPool);
            sequence.InPool = true;
#endif
            _sequenceBag.Add(sequence);
        }

        internal void ReturnByteBuffer(byte[] arrayPoolBuffer)
        {
            ArrayPool<byte>.Shared.Return(arrayPoolBuffer);
        }

        internal void ReturnSegment(Sequence.Segment segment)
        {
            _segmentBag.Add(segment);
        }

        internal Sequence.Segment RentSegment()
        {
            if (_segmentBag.TryTake(out Sequence.Segment? segment))
            {
                return segment!;
            }
            else
            {
                return new Sequence.Segment();
            }
        }

        internal byte[] RentByteBuffer(int sizeHint /* ignored */)
        {
            return ArrayPool<byte>.Shared.Rent(minimumLength: Constants.BufferSize);
        }
    }
}