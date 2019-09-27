// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
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

        public byte ReadByte()
        {
            if (_reader.TryRead(out byte b))
            {
                return b;
            }
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            return 0;
        }

        public byte ReadByte(byte expectedValue)
        {
            byte value = ReadByte();
            if (value != expectedValue)
            {
                ThrowHelper.ThrowProtocolUnexpectedValue();
            }
            return value;
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

        public string ReadUtf8String()
        {
            return ReadString(isUtf8: true);
        }

        public string ReadAsciiString()
        {
            return ReadString(isUtf8: false);
        }

        private string ReadString(bool isUtf8)
        {
            long length = ReadUInt32();
            try
            {
                ReadOnlySpan<byte> span = _reader.UnreadSpan.Length >= length ?
                    _reader.UnreadSpan.Slice(0, (int)length) :
                    _reader.Sequence.Slice(_reader.Position, length).ToArray(); // TODO: maybe stackalloc if length is small
                _reader.Advance(length);
                if (isUtf8)
                {
                    return GetUtf8String(span);
                }
                else
                {
                    return GetAsciiString(span);
                }
            }
            catch (ArgumentOutOfRangeException)
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
                throw;
            }
        }

        private string GetUtf8String(ReadOnlySpan<byte> span)
        {
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

        public string[] ReadNameList()
        {
            long length = ReadUInt32();
            if (length == 0)
            {
                return Array.Empty<string>();
            }

            List<string> names = new List<string>();

            if (TryRead(length, out ReadOnlySequence<byte> namesSequence))
            {
                SequenceReader<byte> namesReader = new SequenceReader<byte>(namesSequence);

                while (namesReader.TryReadTo(out ReadOnlySequence<byte> nameSequence, (byte)','))
                {
                    string name = GetAsciiString(nameSequence);
                    names.Add(name);
                }

                names.Add(GetAsciiString(namesReader.Sequence.Slice(namesReader.Position)));
            }
            else
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            }

            return names.ToArray();
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
                        _reader.Sequence.Slice(_reader.Position, length).ToArray(); // TODO: maybe stackalloc if length is small

                _reader.Advance(length);

                return new BigInteger(span, isUnsigned: false, isBigEndian: true);
            }
            catch (ArgumentOutOfRangeException)
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
                throw;
            }
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

        private string GetAsciiString(ReadOnlySequence<byte> sequence)
        {
            ReadOnlySpan<byte> span = sequence.IsSingleSegment ?
                sequence.FirstSpan :
                sequence.ToArray(); // TODO: maybe stackalloc if length is small
            string name = GetAsciiString(span);
            return name;
        }

        private string GetAsciiString(ReadOnlySpan<byte> span)
        {
            // The ASCIIEncoding class does not provide error detection. For security reasons, you should use the UTF8Encoding, UnicodeEncoding, or UTF32Encoding class and enable error detection.
            try
            {
                // TODO: check if all characters are ASCII (that is: < 128)
                return s_utf8Encoding.GetString(span);
            }
            catch (DecoderFallbackException)
            {
                ThrowHelper.ThrowProtocolInvalidAscii();
                throw;
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

        private ReadOnlySequence<byte> GetUnusedSequence()
        {
            return _reader.Sequence.Slice(_reader.Position);
        }

    }
}