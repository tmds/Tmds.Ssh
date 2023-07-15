// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers.Binary;
using System.Text;
using System.Collections.Generic;

namespace Tmds.Ssh
{
    public partial class SftpClient
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

            public void WriteAttributes(FileAttributes? attributes)
            {
                if (attributes is null)
                {
                    WriteUInt(0);
                }
                else
                {
                    WriteAttributes(attributes.Length, attributes.Uid, attributes.Gid, attributes.FileMode, attributes.LastAccessTime, attributes.LastWriteTime, attributes.ExtendedAttributes);
                }
            }

            public void WriteAttributes(
                long? length = default,
                int? uid = default,
                int? gid = default,
                PosixFileMode? fileMode = default,
                DateTimeOffset? lastAccessTime = default,
                DateTimeOffset? lastWriteTime = default,
                Dictionary<string, string>? extendedAttributes = default
            )
            {
                uint flags = 0;
                if (length.HasValue)
                {
                    flags |= 1;
                }
                if (uid.HasValue || gid.HasValue)
                {
                    if (!uid.HasValue)
                    {
                        throw new ArgumentException(nameof(uid));
                    }
                    if (!gid.HasValue)
                    {
                        throw new ArgumentException(nameof(gid));
                    }
                    flags |= 2;
                }
                if (fileMode.HasValue)
                {
                    flags |= 4;
                }
                if (lastAccessTime.HasValue || lastWriteTime.HasValue)
                {
                    if (!lastAccessTime.HasValue)
                    {
                        throw new ArgumentException(nameof(lastAccessTime));
                    }
                    if (!lastWriteTime.HasValue)
                    {
                        throw new ArgumentException(nameof(lastWriteTime));
                    }
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
                if (uid.HasValue)
                {
                    WriteInt(uid.Value);
                }
                if (gid.HasValue)
                {
                    WriteInt(gid.Value);
                }
                if (fileMode.HasValue)
                {
                    WriteInt((int)fileMode.Value);
                }
                if (lastAccessTime.HasValue)
                {
                    WriteInt((int)lastAccessTime.Value.ToUnixTimeSeconds());
                }
                if (lastWriteTime.HasValue)
                {
                    WriteInt((int)lastWriteTime.Value.ToUnixTimeSeconds());
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

            public unsafe void WriteString(string value)
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
            await ExecuteAsync<object?>(packet, id, pendingOperation, cancellationToken);
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
                int result = await new ValueTask<int>(pendingOperation, pendingOperation.Token);
                return (T)(object)result;
            }
            else
            {
                object? result = await new ValueTask<object?>(pendingOperation, pendingOperation.Token);
                return (T)result!;
            }
        }
    }
}