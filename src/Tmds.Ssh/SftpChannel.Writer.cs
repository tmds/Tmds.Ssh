// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers.Binary;
using System.Text;
using System.Collections.Generic;

namespace Tmds.Ssh;

partial class SftpChannel
{
    private static readonly UTF8Encoding s_utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    // Represents an outgoing packet.
    struct Packet : IDisposable
    {
        private int _length;
        private byte[] _buffer;

        private const int HeaderLength = 5;
        private const int DefaultBufferSize = 4096;

        public const int MaxHandleStringLength = 4 + 256; // The file handle strings MUST NOT be longer than 256 bytes.

        public Packet(PacketType type, int payloadSize = DefaultBufferSize - HeaderLength)
        {
            _length = 0;
            _buffer = ArrayPool<byte>.Shared.Rent(payloadSize + HeaderLength);
            WriteUInt(0);          // length
            WriteByte((byte)type);
        }

        public void WriteByte(byte value)
        {
            _buffer[_length] = value;
            _length += 1;
        }

        public void WriteUInt(uint value)
        {
            BinaryPrimitives.WriteUInt32BigEndian(_buffer.AsSpan(_length), value);
            _length += 4;
        }

        public ReadOnlyMemory<byte> Data
        {
            get
            {
                BinaryPrimitives.WriteInt32BigEndian(_buffer, _length - 4);
                return new ReadOnlyMemory<byte>(_buffer, 0, _length);
            }
        }

        public void Dispose()
        {
            ArrayPool<byte>.Shared.Return(_buffer);
            _buffer = null!;
        }

        internal void WriteInt(int value)
        {
            BinaryPrimitives.WriteInt32BigEndian(_buffer.AsSpan(_length), value);
            _length += 4;
        }

        internal void WriteInt64(long value)
        {
            BinaryPrimitives.WriteInt64BigEndian(_buffer.AsSpan(_length), value);
            _length += 8;
        }

        public void WriteAttributes(
            long? length = default,
            (int Uid, int Gid)? ids = default,
            UnixFilePermissions? permissions = default,
            UnixFileType? fileType = default,
            (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
            Dictionary<string, string>? extendedAttributes = default
        )
        {
            bool setMode = permissions.HasValue;
            uint flags = 0;
            if (length.HasValue)
            {
                flags |= 1;
            }
            if (ids.HasValue)
            {
                flags |= 2;
            }
            if (setMode)
            {
                flags |= 4;
            }
            if (times.HasValue)
            {
                flags |= 8;
            }
            if (extendedAttributes is not null && extendedAttributes.Count > 0)
            {
                flags |= 0x80000000;
            }
            WriteUInt(flags);
            if (length.HasValue)
            {
                WriteInt64(length.Value);
            }
            if (ids.HasValue)
            {
                WriteInt(ids.Value.Uid);
                WriteInt(ids.Value.Gid);
            }
            if (setMode)
            {
                WriteFileMode(permissions, fileType);
            }
            if (times.HasValue)
            {
                WriteUInt(checked((uint)times.Value.LastAccess.ToUnixTimeSeconds()));
                WriteUInt(checked((uint)times.Value.LastWrite.ToUnixTimeSeconds()));
            }
            if (extendedAttributes is not null && extendedAttributes.Count > 0)
            {
                WriteInt(extendedAttributes.Count);
                foreach (var pair in extendedAttributes)
                {
                    WriteString(pair.Key);
                    WriteString(pair.Value);
                }
            }
        }

        private void WriteFileMode(UnixFilePermissions? permissions, UnixFileType? fileType)
        {
            int mode = 0;
            if (permissions.HasValue)
            {
                mode |= permissions.Value.GetMode();
            }
            if (fileType.HasValue)
            {
                mode |= fileType.Value.GetMode();
            }
            WriteInt(mode);
        }

        public unsafe void WriteString(ReadOnlySpan<char> value)
        {
            byte[]? poolBuffer = null;

            int maxLength = s_utf8Encoding.GetMaxByteCount(value.Length);

            // The compiler doesn't like it when we stackalloc into a Span
            // and pass that to Write. It wants to avoid us storing the Span in this instance.
            byte* stackBuffer = stackalloc byte[maxLength <= StackallocThreshold ? maxLength : 0];
            Span<byte> byteSpan = stackBuffer != null ?
                new Span<byte>(stackBuffer, maxLength) :
                (poolBuffer = ArrayPool<byte>.Shared.Rent(maxLength));

            int bytesWritten = s_utf8Encoding.GetBytes(value, byteSpan);

            WriteInt(bytesWritten);
            WriteSpan(byteSpan.Slice(0, bytesWritten));

            if (poolBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(poolBuffer);
            }
        }

        public unsafe void WriteString(ReadOnlyMemory<byte> value)
        {
            WriteInt(value.Length);
            WriteSpan(value.Span);
        }

        public static int GetStringLength(ReadOnlySpan<byte> value)
            => 4 + value.Length;

        private void WriteSpan(ReadOnlySpan<byte> value)
        {
            value.CopyTo(_buffer.AsSpan(_length));
            _length += value.Length;
        }

        private const int StackallocThreshold = 256;
    }

    private async ValueTask ExecuteAsync(
        Packet packet,
        int id,
        PendingOperation? pendingOperation,
        CancellationToken cancellationToken)
    {
        await ExecuteAsync<object?>(packet, id, pendingOperation, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<T> ExecuteAsync<T>(
        Packet packet,
        int id,
        PendingOperation? pendingOperation,
        CancellationToken cancellationToken)
    {
        CancellationTokenRegistration ctr;

        if (pendingOperation is not null)
        {
            ctr = pendingOperation.RegisterForCancellation(cancellationToken);

            // Track the pending operation before queueing the send.
            _pendingOperations[id] = pendingOperation;
        }

        bool sendQueued = _pendingSends.Writer.TryWrite(packet);

        if (!sendQueued)
        {
            packet.Dispose();

            if (_pendingOperations.TryRemove(id, out _))
            {
                pendingOperation?.HandleClose();
            }
        }

        if (pendingOperation is null)
        {
            return default!;
        }

        if (typeof(T) == typeof(int))
        {
            int result = await new ValueTask<int>(pendingOperation, pendingOperation.Token).ConfigureAwait(false);
            return (T)(object)result;
        }
        else
        {
            object? result = await new ValueTask<object?>(pendingOperation, pendingOperation.Token).ConfigureAwait(false);
            return (T)result!;
        }
    }
}
