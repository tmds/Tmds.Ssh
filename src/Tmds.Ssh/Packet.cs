// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading;

namespace Tmds.Ssh
{
    // Wraps a sequence that is an SSH binary packet (https://tools.ietf.org/html/rfc4253#section-6).
    // Functions that accept this type are responsible for Disposing it.
    // A packet can be passed to another function:
    // - as a ReadOnlyPacket, that function is not responsible for disposing the packet.
    // - by calling Clone(), the caller receives a copy of the Packet, which it should Dispose.
    // - by calling Move(), the caller receives the Packet, it can no longer be used by the current function.
    struct Packet : IDisposable
    {
        private const int HeaderLength = 5;
        private const int MinMsgLength = HeaderLength + 1;
        private const int PaddingOffset = 4;
        private const int MsgTypeOffset = 5;

        private Sequence? _sequence;

        public Packet(Sequence? sequence, bool checkHeader = true)
        {
            if (sequence != null)
            {
                if (sequence.IsEmpty)
                {
                    // Reserve some room for the header.
                    Span<byte> header = sequence.AllocGetSpan(HeaderLength);
                    header.Slice(0, HeaderLength).Clear();
                    sequence.AppendAlloced(HeaderLength);
                }
                else if (checkHeader)
                {
                    if (sequence.FirstSpan.Length < MinMsgLength)
                    {
                        ThrowHelper.ThrowProtocolInvalidPacketLength();
                    }

                    Span<byte> firstSpan = sequence.FirstSpan;
                    BinaryPrimitives.TryReadUInt32BigEndian(firstSpan, out uint packet_length);
                    byte padding_length = firstSpan[PaddingOffset];
                    if (sequence.Length != packet_length + 4 ||
                        padding_length > (packet_length - 1))
                    {
                        ThrowHelper.ThrowProtocolInvalidPacketLength();
                    }
                    // MAYDO: remove padding.
                }
            }
            _sequence = sequence;
        }

        public bool IsEmpty
            => _sequence == null || _sequence.IsEmpty;

        public void Dispose()
        {
            _sequence?.Dispose();
            _sequence = null;
        }

        public Packet Move()
        {
            Sequence? sequence = _sequence;
            _sequence = null;
            return new Packet(sequence, checkHeader: false);
        }

        public Packet Clone()
        {
            return new Packet(_sequence?.Clone(), checkHeader: false);
        }

        public ReadOnlySequence<byte> Payload
        {
            get
            {
                if (_sequence == null)
                {
                    return default;
                }

                long payloadLength = PayloadLength;
                if (payloadLength == 0)
                {
                    return default;
                }

                return _sequence.AsReadOnlySequence().Slice(MsgTypeOffset, payloadLength);
            }
        }

        public Span<byte> PayloadHeader
        {
            get
            {
                if (_sequence == null)
                {
                    return default;
                }

                long payloadLength = PayloadLength;
                if (payloadLength == 0)
                {
                    return default;
                }

                Span<byte> span = _sequence.FirstSpan;

                // Check whether the header bytes have been filled in.
                for (int i = PaddingOffset; i >= 0; i--)
                {
                    if (span[i] != 0)
                    {
                        ThrowPacketReadOnly();
                    }
                }

                return span.Slice(MsgTypeOffset);
            }
        }

        public long PayloadLength
        {
            get
            {
                if (_sequence == null)
                {
                    return 0;
                }

                long sequenceLength = _sequence.Length;
                if (sequenceLength < HeaderLength)
                {
                    return 0;
                }

                return sequenceLength - HeaderLength - _sequence.FirstSpan[PaddingOffset];
            }
        }

        public MessageId? MessageId
        {
            get
            {
                if (_sequence == null)
                {
                    return null;
                }

                long sequenceLength = _sequence.Length;
                if (sequenceLength < MinMsgLength)
                {
                    return null;
                }

                return (MessageId)_sequence.FirstSpan[MsgTypeOffset];
            }
        }

        public SequenceReader GetReader() =>
            new SequenceReader(Payload);

        public SequenceWriter GetWriter()
        {
            if (_sequence == null)
            {
                ThrowSequenceEmpty();
            }

            // Check whether the header bytes have been filled in.
            for (int i = PaddingOffset; i >= 0; i--)
            {
                if (_sequence.FirstSpan[i] != 0)
                {
                    ThrowPacketReadOnly();
                }
            }

            return new SequenceWriter(_sequence);
        }

        public void WriteHeaderAndPadding(byte paddingLength)
        {
            GetWriter().WriteRandomBytes(paddingLength);

            Span<byte> firstSpan = _sequence!.FirstSpan;
            BinaryPrimitives.WriteUInt32BigEndian(firstSpan, (uint)(_sequence.Length - 4));
            firstSpan[PaddingOffset] = paddingLength;
        }

        internal ReadOnlySequence<byte> AsReadOnlySequence()
        {
            if (_sequence == null)
            {
                return default;
            }

            return _sequence.AsReadOnlySequence();
        }

        [DoesNotReturn]
        private static void ThrowSequenceEmpty()
        {
            throw new InvalidOperationException("The sequence is empty.");
        }

        [DoesNotReturn]
        private static void ThrowPacketReadOnly()
        {
            throw new InvalidOperationException("The packet is readonly.");
        }

        public Sequence MovePayload()
        {
            if (_sequence == null)
            {
                ThrowSequenceEmpty();
            }

            var sequence = _sequence;
            _sequence = null;

            // Remove padding.
            sequence.RemoveBack(sequence.FirstSpan[PaddingOffset]);
            // Remove header.
            sequence.Remove(HeaderLength);

            return sequence;
        }
    }
}