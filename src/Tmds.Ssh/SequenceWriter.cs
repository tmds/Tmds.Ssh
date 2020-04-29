// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Numerics;
using System.Text;

namespace Tmds.Ssh
{
    ref struct SequenceWriter
    {
        private static readonly UTF8Encoding s_utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        private readonly Sequence? _sequence;
        private Span<byte> _unused;

        public SequencePool SequencePool
            => Sequence.SequencePool;

        public Sequence Sequence
        {
            get
            {
                if (_sequence == null)
                {
                    ThrowHelper.ThrowArgumentNull(nameof(_sequence));
                }

                return _sequence;
            }
        }

        public SequenceWriter(Sequence sequence)
        {
            if (sequence == null)
            {
                ThrowHelper.ThrowArgumentNull(nameof(sequence));
            }

            _sequence = sequence;
            _unused = default;
        }

        private Span<byte> AllocGetSpan(int sizeHint = 0)
        {
            if (_unused.Length <= sizeHint)
            {
                EnlargeUnused(sizeHint);
            }

            return _unused;
        }

        private void EnlargeUnused(int sizeHint)
        {
            _unused = Sequence.AllocGetSpan(sizeHint);
        }

        private void AppendAlloced(int length)
        {
            _unused = _unused.Slice(length);
            Sequence.AppendAlloced(length);
        }

        public void WriteByte(byte value)
        {
            var span = AllocGetSpan(1);
            span[0] = value;
            AppendAlloced(1);
        }

        public void WriteMessageId(MessageId value)
        {
            var span = AllocGetSpan(1);
            span[0] = (byte)value;
            AppendAlloced(1);
        }

        public void WriteUInt32(uint value)
        {
            var span = AllocGetSpan(4);
            BinaryPrimitives.WriteUInt32BigEndian(span, value);
            AppendAlloced(4);
        }

        public void WriteUInt32(int value)
            => WriteUInt32((uint)value);

        public void WriteUInt64(ulong value)
        {
            Debug.Assert(8 <= Constants.GuaranteedSizeHint);

            var span = AllocGetSpan(8);
            BinaryPrimitives.WriteUInt64BigEndian(span, value);
            AppendAlloced(8);
        }

        public void WriteBoolean(bool value)
        {
            WriteByte(value ? (byte)1 : (byte)0);
        }

        public void WriteString(ReadOnlySpan<byte> value)
        {
            WriteUInt32(value.Length);
            Write(value);
        }

        public void WriteString(ReadOnlySequence<byte> value)
        {
            WriteUInt32((uint)value.Length);
            Write(value);
        }

        public void WriteString(string value)
        {
            Write(value.AsSpan(), writeLength: true);
        }

        public void WriteString(Name value)
        {
            WriteString(value.AsSpan());
        }

        public void WriteNameList(List<Name> names)
        {
            var lengthSpan = AllocGetSpan(4);
            AppendAlloced(4);

            int bytesWritten = 0;

            for (int i = 0; i < names.Count; i++)
            {
                ReadOnlySpan<byte> span = names[i].AsSpan();
                Write(span);
                bytesWritten += span.Length;
                if (i != names.Count - 1)
                {
                    WriteByte((byte)',');
                    bytesWritten++;
                }
            }

            BinaryPrimitives.WriteUInt32BigEndian(lengthSpan, (uint)bytesWritten);
        }

        public void WriteMPInt(BigInteger value)
        {
            if (value == BigInteger.Zero)
            {
                WriteUInt32(0);
            }
            else
            {
                int length = value.GetByteCount(isUnsigned: false);
                WriteUInt32(length);

                var span = AllocGetSpan(length);
                if (span.Length <= length)
                {
                    value.TryWriteBytes(span, out int bytesWritten, isUnsigned: false, isBigEndian: true);
                    Debug.Assert(bytesWritten == length);
                    AppendAlloced(bytesWritten);
                }
                else
                {
                    byte[] buffer = ArrayPool<byte>.Shared.Rent(length);

                    value.TryWriteBytes(buffer, out int bytesWritten, isUnsigned: false, isBigEndian: true);
                    Write(buffer.AsSpan().Slice(0, length));
                    Debug.Assert(bytesWritten == length);

                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
        }

        public void WriteMPInt(ReadOnlySpan<byte> value)
        {
            // MAYDO: avoid allocations.
            BigInteger bi = new BigInteger(value, isUnsigned: true, isBigEndian: true);
            WriteMPInt(bi);
        }

        public void Write(in ReadOnlySequence<byte> value)
        {
            if (value.IsSingleSegment)
            {
                Write(value.FirstSpan);
            }
            else
            {
                foreach (var segment in value)
                {
                    Write(segment.Span);
                }
            }
        }

        public void Write(ReadOnlySpan<byte> value)
        {
            if (value.Length == 0)
            {
                return;
            }

            Span<byte> span = AllocGetSpan();

            // Fast path, try copying to the available memory directly
            if (value.Length <= span.Length)
            {
                value.CopyTo(span);
                AppendAlloced(value.Length);
            }
            else
            {
                WriteMultiple(value, span);
            }
        }

        public void Reserve(int count)
        {
            while (count > 0)
            {
                Span<byte> span = AllocGetSpan(count);
                int spanCount = Math.Min(count, span.Length);
                span.Slice(0, spanCount).Clear();
                AppendAlloced(spanCount);
                count -= spanCount;
            }
        }

        public void WriteRandomBytes(int count)
        {
            Span<byte> span = AllocGetSpan(count);

            if (span.Length <= count)
            {
                span = span.Slice(0, count);
                RandomBytes.Fill(span);
                AppendAlloced(count);
            }
            else
            {
                // MAYDO: maybe stackalloc for small counts

                byte[] buffer = ArrayPool<byte>.Shared.Rent(count);

                span = buffer.AsSpan().Slice(0, count);
                RandomBytes.Fill(span);
                Write(span);

                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public void WriteString(ECPoint point)
        {
            WriteUInt32(1 + point.X.Length * 2);
            WriteByte(0x04); // No compression.
            Write(point.X);
            Write(point.Y);
        }

        private void WriteMultiple(ReadOnlySpan<byte> input, Span<byte> destination)
        {
            while (true)
            {
                int writeSize = Math.Min(destination.Length, input.Length);
                input.Slice(0, writeSize).CopyTo(destination);
                AppendAlloced(writeSize);
                input = input.Slice(writeSize);
                if (input.Length == 0)
                {
                    break;
                }
                destination = AllocGetSpan();
            }
        }

        private unsafe int Write(ReadOnlySpan<char> value, bool writeLength)
        {
            byte[]? poolBuffer = null;

            int maxLength = s_utf8Encoding.GetMaxByteCount(value.Length);

            // The compiler doesn't like it when we stackalloc into a Span
            // and pass that to Write. It wants to avoid us storing the Span in this instance.
            byte* stackBuffer = stackalloc byte[maxLength <= Constants.StackallocThreshold ? maxLength : 0];
            Span<byte> byteSpan = stackBuffer != null ?
                new Span<byte>(stackBuffer, maxLength) :
                (poolBuffer = ArrayPool<byte>.Shared.Rent(maxLength));

            int bytesWritten = s_utf8Encoding.GetBytes(value, byteSpan);

            if (writeLength)
            {
                WriteUInt32(bytesWritten);
            }
            Write(byteSpan.Slice(0, bytesWritten));

            if (poolBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(poolBuffer);
            }

            return bytesWritten;
        }
    }
}