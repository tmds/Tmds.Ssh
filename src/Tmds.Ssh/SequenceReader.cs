// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Linq;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Tmds.Ssh
{
    ref struct SequenceReader
    {
        private static readonly UTF8Encoding s_utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        private SequenceReader<byte> _reader;

        public long Length => _reader.Length;
        public long Remaining => _reader.Remaining;
        public long Consumed => _reader.Consumed;

        public SequenceReader(Sequence sequence)
        {
            if (sequence == null)
            {
                ThrowHelper.ThrowArgumentNull(nameof(sequence));
            }

            _reader = new SequenceReader<byte>(sequence.AsReadOnlySequence());
        }

        public SequenceReader(byte[] array)
        {
            if (array == null)
            {
                ThrowHelper.ThrowArgumentNull(nameof(array));
            }

            _reader = new SequenceReader<byte>(new ReadOnlySequence<byte>(array));
        }

        public SequenceReader(ReadOnlySequence<byte> data)
        {
            _reader = new SequenceReader<byte>(data);
        }

        public byte ReadByte()
        {
            if (_reader.TryRead(out byte b))
            {
                return b;
            }
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            return 0;
        }

        public void ReadByte(byte expectedValue)
        {
            byte value = ReadByte();
            if (value != expectedValue)
            {
                ThrowHelper.ThrowProtocolUnexpectedValue();
            }
        }

        public MessageId ReadMessageId()
        {
            return (MessageId)ReadByte();
        }

        public void ReadMessageId(MessageId expectedValue)
        {
            MessageId value = ReadMessageId();
            if (value != expectedValue)
            {
                ThrowHelper.ThrowProtocolUnexpectedValue();
            }
        }

        public SftpPacketType ReadSftpPacketType()
        {
            return (SftpPacketType)ReadByte();
        }

        public void ReadSftpPacketType(SftpPacketType expectedValue)
        {
            SftpPacketType value = ReadSftpPacketType();
            if (value != expectedValue)
            {
                ThrowHelper.ThrowProtocolUnexpectedValue();
            }
        }

        public uint ReadUInt32()
        {
            if (_reader.TryReadBigEndian(out int i))
            {
                return unchecked((uint)i);
            }
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            return 0;
        }

        public void SkipUInt32()
        {
            Skip(4);
        }

        public uint ReadUInt32(uint expectedValue)
        {
            uint value = ReadUInt32();
            if (value != expectedValue)
            {
                ThrowHelper.ThrowProtocolUnexpectedValue();
            }
            return value;
        }

        public bool ReadBoolean()
        {
            return ReadByte() != 0;
        }

        public void SkipBoolean()
        {
            Skip(1);
        }

        public ulong ReadUInt64()
        {
            if (_reader.TryReadBigEndian(out long i))
            {
                return unchecked((ulong)i);
            }
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            return 0;
        }

        public ReadOnlySequence<byte> ReadStringAsBytes()
        {
            long length = ReadUInt32();
            if (TryRead(length, out ReadOnlySequence<byte> value))
            {
                return value;
            }
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            return default;
        }

        public ReadOnlySequence<byte> ReadStringAsBytes(int maxLength)
        {
            ReadOnlySequence<byte> data = ReadStringAsBytes();
            if (data.Length > maxLength)
            {
                ThrowHelper.ThrowProtocolStringTooLong();
            }
            return data;
        }

        public SshKey ReadSshKey(IReadOnlyList<Name> allowedFormats)
        {
            ReadOnlySequence<byte> key = ReadStringAsBytes(Constants.MaxKeyLength);
            SequenceReader keyReader = new SequenceReader(key);
            Name type = keyReader.ReadName(allowedFormats);
            return new SshKey(type.ToString(), key.ToArray());
        }

        public void SkipString()
        {
            long length = ReadUInt32();
            Skip(length);
        }

        public string ReadUtf8String()
        {
            long length = ReadUInt32();
            try
            {
                ReadOnlySpan<byte> span = _reader.UnreadSpan.Length >= length ?
                    _reader.UnreadSpan.Slice(0, (int)length) :
                    _reader.Sequence.Slice(_reader.Position, length).ToArray(); // MAYDO: maybe stackalloc if length is small
                _reader.Advance(length);
                try
                {
                    return s_utf8Encoding.GetString(span);
                }
                catch (DecoderFallbackException)
                {
                    ThrowHelper.ThrowProtocolInvalidUtf8();
                    throw;
                }
            }
            catch (ArgumentOutOfRangeException)
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
                throw;
            }
        }

        public Name ReadName()
        {
            long length = ReadUInt32();
            return ReadName(length);
        }

        public void ReadName(Name expected)
        {
            // MAYDO: implement without allocating.
            if (ReadName() != expected)
            {
                ThrowHelper.ThrowProtocolUnexpectedValue();
            }
        }

        public Name ReadName(IReadOnlyList<Name> allowedNames)
        {
            var name = ReadName();
            if (!allowedNames.Contains(name))
            {
                ThrowHelper.ThrowProtocolUnexpectedValue();
                return default;
            }

            return name;
        }

        private Name ReadName(long length)
        {
            if (length > Constants.MaxNameLength)
            {
                ThrowHelper.ThrowProtocolNameTooLong();
            }

            try
            {
                byte[] bytes = _reader.UnreadSpan.Length >= length ?
                                 _reader.UnreadSpan.Slice(0, (int)length).ToArray() :
                                 _reader.Sequence.Slice(_reader.Position, length).ToArray();

                _reader.Advance(length);

                if (!Name.TryCreate(bytes, out Name name))
                {
                    ThrowHelper.ThrowProtocolInvalidName();
                }

                return name;
            }
            catch (ArgumentOutOfRangeException)
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
                throw;
            }
        }

        public Name[] ReadNameList()
        {
            long length = ReadUInt32();
            if (length == 0)
            {
                return Array.Empty<Name>();
            }

            List<Name> names = new List<Name>();

            if (TryRead(length, out ReadOnlySequence<byte> namesSequence))
            {
                SequenceReader<byte> namesReader = new SequenceReader<byte>(namesSequence);

                while (namesReader.TryReadTo(out ReadOnlySequence<byte> nameSequence, (byte)','))
                {
                    Name name = ReadName(nameSequence);
                    names.Add(name);
                }

                names.Add(ReadName(namesReader.Sequence.Slice(namesReader.Position)));
            }
            else
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            }

            return names.ToArray();

            static Name ReadName(ReadOnlySequence<byte> nameSequence)
            {
                if (nameSequence.Length > Constants.MaxNameLength)
                {
                    ThrowHelper.ThrowProtocolNameTooLong();
                }

                byte[] bytes = nameSequence.ToArray();
                if (!Name.TryCreate(bytes, out Name name))
                {
                    ThrowHelper.ThrowProtocolInvalidName();
                }

                return name;
            }
        }

        public BigInteger ReadMPInt()
        {
            long length = ReadUInt32();
            if (length == 0)
            {
                return BigInteger.Zero;
            }
            try
            {
                ReadOnlySpan<byte> span = _reader.UnreadSpan.Length >= length ?
                        _reader.UnreadSpan.Slice(0, (int)length) :
                        _reader.Sequence.Slice(_reader.Position, length).ToArray(); // MAYDO: maybe stackalloc if length is small

                _reader.Advance(length);

                return new BigInteger(span, isUnsigned: false, isBigEndian: true);
            }
            catch (ArgumentOutOfRangeException)
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
                throw;
            }
        }

        public ECPoint ReadStringAsECPoint()
        {
            long length = ReadUInt32();
            if (length == 0)
            {
                ThrowHelper.ThrowProtocolECPointInvalidLength();
            }
            if (length > Constants.MaxECPointLength)
            {
                ThrowHelper.ThrowProtocolECPointTooLong();
            }

            byte firstByte = ReadByte();
            if (firstByte != 0x04) // Check uncompressed.
            {
                ThrowHelper.ThrowNotSupportedException("Reading compressed ECPoints is not supported.");
            }
            length--;

            if (length % 2 != 0)
            {
                ThrowHelper.ThrowProtocolECPointInvalidLength();
            }

            return new ECPoint
            {
                X = ReadBytes(length / 2),
                Y = ReadBytes(length / 2)
            };
        }

        public void Skip(long count)
        {
            try
            {
                _reader.Advance(count);
            }
            catch (ArgumentOutOfRangeException)
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            }
        }

        public void ReadEnd()
        {
            if (Remaining != 0)
            {
                ThrowHelper.ThrowProtocolPacketLongerThanExpected();
            }
        }

        // This will be added in https://github.com/dotnet/corefx/issues/40962.
        public bool TryRead(long length, out ReadOnlySequence<byte> value)
        {
            SequencePosition start = _reader.Position;
            try
            {
                _reader.Advance(length);
            }
            catch (ArgumentOutOfRangeException)
            {
                value = default;
                return false;
            }
            SequencePosition end = _reader.Position;
            value = _reader.Sequence.Slice(start, end);
            return true;
        }

        private byte[] ReadBytes(long length)
        {
            try
            {
                byte[] bytes = _reader.UnreadSpan.Length >= length ?
                        _reader.UnreadSpan.Slice(0, (int)length).ToArray() :
                        _reader.Sequence.Slice(_reader.Position, length).ToArray();

                _reader.Advance(length);

                return bytes;
            }
            catch (ArgumentOutOfRangeException)
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
                throw;
            }
        }
    }
}