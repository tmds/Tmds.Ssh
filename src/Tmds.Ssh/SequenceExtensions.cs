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
    // https://tools.ietf.org/html/rfc4251#section-5
    static class SequenceExtensions
    {
        private static readonly UTF8Encoding s_utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        public static void WriteByte(this Sequence sequence, byte value)
        {
            var span = sequence.AllocGetSpan(1);
            span[0] = value;
            sequence.AppendAlloced(1);
        }

        public static void WriteUInt32(this Sequence sequence, uint value)
        {
            var span = sequence.AllocGetSpan(4);
            BinaryPrimitives.WriteUInt32BigEndian(span, value);
            sequence.AppendAlloced(4);
        }

        public static void WriteUInt32(this Sequence sequence, int value)
            => WriteUInt32(sequence, (uint)value);

        public static void WriteUInt64(this Sequence sequence, ulong value)
        {
            Debug.Assert(8 <= Constants.GuaranteedSizeHint);

            var span = sequence.AllocGetSpan(8);
            BinaryPrimitives.WriteUInt64BigEndian(span, value);
            sequence.AppendAlloced(8);
        }

        public static void WriteBoolean(this Sequence sequence, bool value)
        {
            WriteByte(sequence, value ? (byte)1 : (byte)0);
        }

        public static void WriteString(this Sequence sequence, ReadOnlySpan<byte> value)
        {
            sequence.WriteUInt32(value.Length);
            sequence.Write(value);
        }

        public static void WriteString(this Sequence sequence, string value)
        {
            sequence.Write(value.AsSpan(), writeLength: true);
        }

        public static void WriteNameList(this Sequence sequence, List<string> names)
        {
            var lengthSpan = sequence.AllocGetSpan(4);
            sequence.AppendAlloced(4);

            int bytesWritten = 0;

            for (int i = 0; i < names.Count; i++)
            {
                bytesWritten += sequence.Write(names[i].AsSpan(), writeLength: false);
                if (i != names.Count - 1)
                {
                    sequence.WriteByte((byte)',');
                    bytesWritten++;
                }
            }

            BinaryPrimitives.WriteUInt32BigEndian(lengthSpan, (uint)bytesWritten);
        }

        public static void WriteMPInt(this Sequence sequence, BigInteger value)
        {
            if(value == BigInteger.Zero)
            {
                sequence.WriteUInt32(0);
            }
            else
            {
                int length = value.GetByteCount(isUnsigned: false);
                sequence.WriteUInt32(length);

                var span = sequence.AllocGetSpan(length);
                if (span.Length <= length)
                {
                    value.TryWriteBytes(span, out int bytesWritten, isUnsigned: false, isBigEndian: true);
                    Debug.Assert(bytesWritten == length);
                    sequence.AppendAlloced(bytesWritten);
                }
                else
                {
                    byte[] buffer = ArrayPool<byte>.Shared.Rent(length);

                    value.TryWriteBytes(buffer, out int bytesWritten, isUnsigned: false, isBigEndian: true);
                    sequence.Write(buffer.AsSpan().Slice(0, length));
                    Debug.Assert(bytesWritten == length);

                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
        }

        private static int Write(this Sequence sequence, ReadOnlySpan<char> value, bool writeLength)
        {
            byte[]? buffer = null;

            int maxLength = s_utf8Encoding.GetMaxByteCount(value.Length);

            Span<byte> byteSpan = maxLength <= Constants.StackallocThreshold ?
                stackalloc byte[maxLength] :
                (buffer = ArrayPool<byte>.Shared.Rent(maxLength));

            int bytesWritten = s_utf8Encoding.GetBytes(value, byteSpan);

            if (writeLength)
            {
                sequence.WriteUInt32(bytesWritten);
            }
            sequence.Write(byteSpan.Slice(0, bytesWritten));

            if (buffer != null)
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            return bytesWritten;
        }
    }
}