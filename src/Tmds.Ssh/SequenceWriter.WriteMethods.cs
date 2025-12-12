// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Numerics;
using System.Text;

namespace Tmds.Ssh;

ref partial struct SequenceWriter
{
    // -- Start of Write methods --
    // The following method implementations are identical between SequenceWriter and ArrayWriter.
    // They depend only on AllocGetSpan and AppendAlloced.
    // This duplication could be avoided using C# 13 ref struct generics, but we can't use those due to targetting earlier versions.

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
        var span = AllocGetSpan(8);
        BinaryPrimitives.WriteUInt64BigEndian(span, value);
        AppendAlloced(8);
    }

    public void WriteBoolean(bool value)
    {
        WriteByte(value ? (byte)1 : (byte)0);
    }
    
    public void WriteString(byte[] value)
    {
        WriteString(value.AsSpan());
    }

    public void WriteString(ReadOnlySpan<byte> value)
    {
        WriteUInt32(value.Length);
        Write(value);
    }

    public void WriteString(ReadOnlyMemory<byte> value)
    {
        WriteString(value.Span);
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
        WriteString(value.ToString());
    }

    public void WriteNameList(List<Name> names)
    {
        var lengthSpan = AllocGetSpan(4);
        AppendAlloced(4);

        int bytesWritten = 0;

        for (int i = 0; i < names.Count; i++)
        {
            bytesWritten += Write(names[i].ToString(), writeLength: false);
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

    public void Write(scoped ReadOnlySpan<byte> value)
    {
        if (value.Length == 0)
        {
            return;
        }

        Span<byte> span = AllocGetSpan(value.Length);
        value.CopyTo(span);
        AppendAlloced(value.Length);
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
        WriteUInt32(1 + point.X!.Length * 2);
        WriteByte(0x04); // No compression.
        Write(point.X);
        Write(point.Y);
    }

    private unsafe int Write(ReadOnlySpan<char> value, bool writeLength)
    {
        byte[]? poolBuffer = null;

        int maxLength = ProtocolEncoding.UTF8.GetMaxByteCount(value.Length);

        // The compiler doesn't like it when we stackalloc into a Span
        // and pass that to Write. It wants to avoid us storing the Span in this instance.
        byte* stackBuffer = stackalloc byte[maxLength <= Constants.StackallocThreshold ? maxLength : 0];
        Span<byte> byteSpan = stackBuffer != null ?
            new Span<byte>(stackBuffer, maxLength) :
            (poolBuffer = ArrayPool<byte>.Shared.Rent(maxLength));

        int bytesWritten = ProtocolEncoding.UTF8.GetBytes(value, byteSpan);

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
