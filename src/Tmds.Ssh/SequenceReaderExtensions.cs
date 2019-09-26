// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Tmds.Ssh
{
    // https://tools.ietf.org/html/rfc4251#section-5
    static class SequenceReaderExtensions
    {
        private static readonly UTF8Encoding s_utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        public static byte ReadByte(ref this SequenceReader<byte> reader)
        {
            if (reader.TryRead(out byte b))
            {
                return b;
            }
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            return 0;
        }

        public static uint ReadUInt32(ref this SequenceReader<byte> reader)
        {
            if (reader.TryReadBigEndian(out int i))
            {
                return unchecked((uint)i);
            }
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            return 0;
        }

        public static bool ReadBoolean(ref this SequenceReader<byte> reader)
        {
            return reader.ReadByte() != 0;
        }

        public static ulong ReadUInt64(ref this SequenceReader<byte> reader)
        {
            if (reader.TryReadBigEndian(out long i))
            {
                return unchecked((ulong)i);
            }
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            return 0;
        }

        public static ReadOnlySequence<byte> ReadStringAsBytes(ref this SequenceReader<byte> reader)
        {
            long length = reader.ReadUInt32();
            if (reader.TryRead(length, out ReadOnlySequence<byte> value))
            {
                return value;
            }
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            return default;
        }

        public static string ReadUtf8String(ref this SequenceReader<byte> reader)
        {
            return ReadString(ref reader, isUtf8: true);
        }

        public static string ReadAsciiString(ref this SequenceReader<byte> reader)
        {
            return ReadString(ref reader, isUtf8: false);
        }

        private static string ReadString(ref this SequenceReader<byte> reader, bool isUtf8)
        {
            long length = reader.ReadUInt32();
            try
            {
                ReadOnlySpan<byte> span = reader.UnreadSpan.Length >= length ?
                    reader.UnreadSpan.Slice(0, (int)length) :
                    reader.Sequence.Slice(reader.Position, length).ToArray(); // TODO: maybe stackalloc if length is small
                reader.Advance(length);
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

        private static string GetUtf8String(ReadOnlySpan<byte> span)
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

        public static string[] ReadNameList(ref this SequenceReader<byte> reader)
        {
            long length = reader.ReadUInt32();
            if (length == 0)
            {
                return Array.Empty<string>();
            }

            List<string> names = new List<string>();

            if (reader.TryRead(length, out ReadOnlySequence<byte> namesSequence))
            {
                SequenceReader<byte> namesReader = new SequenceReader<byte>(namesSequence);

                while (namesReader.TryReadTo(out ReadOnlySequence<byte> nameSequence, (byte)','))
                {
                    string name = GetAsciiString(nameSequence);
                    names.Add(name);
                }

                names.Add(GetAsciiString(namesReader.GetUnusedSequence()));
            }
            else
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            }

            return names.ToArray();
        }

        public static BigInteger ReadMPInt(ref this SequenceReader<byte> reader)
        {
            long length = reader.ReadUInt32();
            try
            {
                ReadOnlySpan<byte> span = reader.UnreadSpan.Length >= length ?
                        reader.UnreadSpan.Slice(0, (int)length) :
                        reader.Sequence.Slice(reader.Position, length).ToArray(); // TODO: maybe stackalloc if length is small

                return new BigInteger(span, isUnsigned: false, isBigEndian: true);
            }
            catch (ArgumentOutOfRangeException)
            {
                ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
                throw;
            }
        }

        private static string GetAsciiString(ReadOnlySequence<byte> sequence)
        {
            ReadOnlySpan<byte> span = sequence.IsSingleSegment ?
                sequence.FirstSpan :
                sequence.ToArray(); // TODO: maybe stackalloc if length is small
            string name = GetAsciiString(span);
            return name;
        }

        private static string GetAsciiString(ReadOnlySpan<byte> span)
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
        private static bool TryRead(ref this SequenceReader<byte> reader, long length, out ReadOnlySequence<byte> value)
        {
            SequencePosition start = reader.Position;
            try
            {
                reader.Advance(length);
            }
            catch (ArgumentOutOfRangeException)
            {
                value = default;
                return false;
            }
            SequencePosition end = reader.Position;
            value = reader.Sequence.Slice(start, end);
            return true;
        }

        private static ReadOnlySequence<byte> GetUnusedSequence(ref this SequenceReader<byte> reader)
        {
            return reader.Sequence.Slice(reader.Position);
        }
    }
}
