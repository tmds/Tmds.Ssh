// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers.Binary;
using System.Text;

namespace Tmds.Ssh
{
    public partial class SftpClient
    {
        private static readonly UTF8Encoding s_utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        private readonly SemaphoreSlim _writeSemaphore = new SemaphoreSlim(1, 1);

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

        private async ValueTask WritePacketForPendingOperationAsync(
            Packet packet,
            PacketType packetType,
            int id,
            PendingOperation pendingOperation,
            CancellationToken cancellationToken)
        {
            // Serialize packet writing to the channel.
            await _writeSemaphore.WaitAsync(cancellationToken);
            CancellationTokenRegistration ctr = pendingOperation.RegisterForCancellation(cancellationToken);
            try
            {
                _pendingOperations[id] = pendingOperation;
                await _channel.WriteAsync(packet.Data); // Throws if the channel is closed.
            }
            catch
            {
                ctr.Dispose();
                _pendingOperations.TryRemove(id, out _);

                throw;
            }
            finally
            {
                _writeSemaphore.Release();
            }
        }
    }
}