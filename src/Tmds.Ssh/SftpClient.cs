// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using System.IO.Pipelines;
using System.Buffers.Binary;
using System.IO;
using System.Collections.Generic;
using System.Threading.Tasks.Sources;
using System.Text;
using System.Runtime.InteropServices;

namespace Tmds.Ssh
{
    public sealed class SftpClient : IDisposable
    {
        private static readonly UTF8Encoding s_utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
        const uint ProtocolVersion = 3;

        private readonly SshChannel _channel;
        private readonly object _gate = new();
        private readonly Dictionary<int, PendingOperation> _pendingOperations = new();
        private byte[]? _receiveBuffer;
        private int _nextId = 5;

        private int GetNextId() => Interlocked.Increment(ref _nextId);

        internal SftpClient(SshChannel channel)
        {
            _channel = channel;
            _receiveBuffer = new byte[4096];
        }

        public CancellationToken ClientAborted
            => _channel.ChannelAborted;

        public void Dispose()
        {
            _channel.Dispose();
        }

        internal async Task ProtocolInitAsync(CancellationToken cancellationToken)
        {
            using Packet packet = new Packet(PacketType.SSH_FXP_INIT);
            packet.WriteUInt(ProtocolVersion);
            await _channel.WriteAsync(packet.Data, cancellationToken);

            ReadOnlyMemory<byte> versionPacket = await ReadPacketAsync(cancellationToken);
            HandleVersionPacket(versionPacket.Span);

            _ = ReadAllPacketsAsync();
        }

        private async ValueTask<ReadOnlyMemory<byte>> ReadPacketAsync(CancellationToken cancellationToken = default)
        {
            int totalReceived = 0;

            // Read packet length.
            do
            {
                Memory<byte> readBuffer = new Memory<byte>(_receiveBuffer, totalReceived, 4 - totalReceived);
                (ChannelReadType type, int bytesRead) = await _channel.ReadAsync(readBuffer, default, cancellationToken);
                if (type != ChannelReadType.StandardOutput)
                {
                    return default;
                }
                totalReceived += bytesRead;
            } while (totalReceived < 4);

            int packetLength = BinaryPrimitives.ReadInt32BigEndian(_receiveBuffer);
            int totalReceiveLength = packetLength + 4;

            // Ensure receive buffer can fit packet.
            if (_receiveBuffer!.Length < totalReceiveLength)
            {
                _receiveBuffer = new byte[totalReceiveLength];
                BinaryPrimitives.WriteInt32BigEndian(_receiveBuffer, packetLength);
            }

            // Read packet.
            while (totalReceived < totalReceiveLength)
            {
                Memory<byte> readBuffer = new Memory<byte>(_receiveBuffer, totalReceived, _receiveBuffer.Length - totalReceived);
                (ChannelReadType type, int bytesRead) = await _channel.ReadAsync(readBuffer, default, cancellationToken);
                if (type != ChannelReadType.StandardOutput)
                {
                    return default;
                }
                totalReceived += bytesRead;
            }
            return new ReadOnlyMemory<byte>(_receiveBuffer, 4, packetLength);
        }

        private async Task ReadAllPacketsAsync()
        {
            try
            {
                do
                {
                    ReadOnlyMemory<byte> packet = await ReadPacketAsync();
                    if (packet.Length == 0)
                    {
                        break;
                    }
                    int id = BinaryPrimitives.ReadInt32BigEndian(packet.Span.Slice(1));
                    PendingOperation? operation;
                    lock (_gate)
                    {
                        _pendingOperations.Remove(id, out operation);
                    }
                    if (operation is not null)
                    {
                        operation.HandleReply(this, packet.Span);
                    }
                } while (true);
            }
            catch
            { }
            finally
            {
                // Ensure the channel is closed by cancelling it.
                // No more pending operations can be added after this.
                lock (_gate) // Synchronize with WritePacketForPendingOperationAsync.
                {
                    _channel.Cancel();
                }

                foreach (var item in _pendingOperations)
                {
                    var exception = _channel.CreateCloseException(
                                        // Override the cancellation exception.
                                        createCancelException: () => new SshOperationException("Unexpected reply or eof."));
                    item.Value.HandleClose(exception);
                }
                _pendingOperations.Clear();
            }
        }

        private void HandleVersionPacket(ReadOnlySpan<byte> packet)
        {
            PacketType type = (PacketType)packet[0];
            if (type != PacketType.SSH_FXP_VERSION)
            {
                throw new SshOperationException($"Expected packet SSH_FXP_VERSION, but received {type}.");
            }
        }

        enum PacketType : byte
        {
            SSH_FXP_INIT = 1,
            SSH_FXP_VERSION = 2,
            SSH_FXP_OPEN = 3,
            SSH_FXP_CLOSE = 4,
            SSH_FXP_READ = 5,
            SSH_FXP_WRITE = 6,
            SSH_FXP_LSTAT = 7,
            SSH_FXP_FSTAT = 8,
            SSH_FXP_SETSTAT = 9,
            SSH_FXP_FSETSTAT = 10,
            SSH_FXP_OPENDIR = 11,
            SSH_FXP_READDIR = 12,
            SSH_FXP_REMOVE = 13,
            SSH_FXP_MKDIR = 14,
            SSH_FXP_RMDIR = 15,
            SSH_FXP_REALPATH = 16,
            SSH_FXP_STAT = 17,
            SSH_FXP_RENAME = 18,
            SSH_FXP_READLINK = 19,
            SSH_FXP_SYMLINK = 20,
            SSH_FXP_STATUS = 101,
            SSH_FXP_HANDLE = 102,
            SSH_FXP_DATA = 103,
            SSH_FXP_NAME = 104,
            SSH_FXP_ATTRS = 105,
            SSH_FXP_EXTENDED = 200,
            SSH_FXP_EXTENDED_REPLY = 201,
        }

        ref struct PacketReader
        {
            private ReadOnlySpan<byte> _remainder;

            public ReadOnlySpan<byte> Remainder => _remainder;

            public PacketReader(ReadOnlySpan<byte> packet)
            {
                _remainder = packet;
            }

            public uint ReadUInt()
            {
                uint value = BinaryPrimitives.ReadUInt32BigEndian(_remainder);
                _remainder = _remainder.Slice(4);
                return value;
            }

            public int ReadInt()
            {
                int value = BinaryPrimitives.ReadInt32BigEndian(_remainder);
                _remainder = _remainder.Slice(4);
                return value;
            }

            public string ReadString()
            {
                int length = ReadInt();
                string value = s_utf8Encoding.GetString(_remainder.Slice(0, length));
                _remainder = _remainder.Slice(length);
                return value;
            }

            public byte ReadByte()
            {
                byte value = _remainder[0];
                _remainder = _remainder.Slice(1);
                return value;
            }

            public PacketType ReadPacketType()
            {
                return (PacketType)ReadByte();
            }
        }

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

        public async ValueTask<SftpFile> OpenFileAsync(string filename, OpenFlags flags)
        {
            PacketType packetType = PacketType.SSH_FXP_OPEN;

            int id = GetNextId();
            PendingOperation pendingOperation = new(packetType);

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(filename);
            packet.WriteUInt((uint)flags);
            packet.WriteUInt(0); // attrs

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation);

            return (SftpFile)await new ValueTask<object>(pendingOperation, pendingOperation.Token);
        }

        private ValueTask WritePacketForPendingOperationAsync(Packet packet, PacketType packetType, int id, PendingOperation pendingOperation)
        {
            ValueTask writeOperation;
            // Under a lock, add request to the dictionary AFTER writing it.
            lock (_gate)
            {
                writeOperation = _channel.WriteAsync(packet.Data); // Throws if the channel is closed.
                _pendingOperations.Add(id, pendingOperation);
            }

            return writeOperation;
        }

        internal async ValueTask<int> ReadFileAsync(SftpFile file, long offset, Memory<byte> buffer)
        {
            PacketType packetType = PacketType.SSH_FXP_READ;

            int id = GetNextId();
            PendingOperation pendingOperation = new(packetType);
            pendingOperation.Context = file;
            pendingOperation.Buffer = buffer;

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(file.Handle);
            packet.WriteInt64(offset);
            packet.WriteInt(buffer.Length);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation);

            return await new ValueTask<int>(pendingOperation, pendingOperation.Token);
        }

        internal async ValueTask WriteFileAsync(SftpFile file, long offset, ReadOnlyMemory<byte> buffer)
        {
            int writtenTotal = 0;
            try
            {
                while (!buffer.IsEmpty)
                {
                    /*
                        TODO: take into account the max packet size of the channel.

                        All servers SHOULD support packets of at
                        least 34000 bytes (where the packet size refers to the full length,
                        including the header above).  This should allow for reads and writes
                        of at most 32768 bytes.
                    */
                    int writeLength = Math.Min(buffer.Length, 32768);
                    ReadOnlyMemory<byte> writeBuffer = buffer.Slice(0, writeLength);

                    PacketType packetType = PacketType.SSH_FXP_WRITE;

                    int id = GetNextId();
                    PendingOperation pendingOperation = new(packetType);
                    pendingOperation.Context = file;
                    pendingOperation.Buffer = MemoryMarshal.AsMemory(writeBuffer);

                    using Packet packet = new Packet(packetType, payloadSize: 4 /* id */
                                                                + Packet.MaxHandleStringLength
                                                                + 8 /* offset */
                                                                + Packet.GetStringLength(writeBuffer.Span));
                    packet.WriteInt(id);
                    packet.WriteString(file.Handle);
                    packet.WriteInt64(offset + writtenTotal);
                    packet.WriteString(writeBuffer);

                    await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation);

                    await new ValueTask<object>(pendingOperation, pendingOperation.Token);

                    buffer = buffer.Slice(writeLength);
                    writtenTotal += writeLength;

                    file.IncreaseOffset(writeLength);
                }
            }
            finally
            {
                file.CompleteOperation(0);
            }
        }

        internal void CloseFile(string handle)
        {
            int id = GetNextId();

            using Packet packet = new Packet(PacketType.SSH_FXP_CLOSE);
            packet.WriteInt(id);
            packet.WriteString(handle);

            _ = _channel.WriteAsync(packet.Data);
        }

        internal async ValueTask CloseFileAsync(string handle)
        {
            PacketType packetType = PacketType.SSH_FXP_CLOSE;

            int id = GetNextId();
            PendingOperation pendingOperation = new(packetType);

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation);

            await new ValueTask<object>(pendingOperation, pendingOperation.Token);
        }

        sealed class PendingOperation : IValueTaskSource<object>, IValueTaskSource<int>
        {
            private ManualResetValueTaskSourceCore<object> _core;
            private int IntResult;

            private void SetIntResult(int value)
            {
                IntResult = value;
                _core.SetResult(null!);
            }

            public short Token => _core.Version;

            public object Context { get; set; }
            public Memory<byte> Buffer { get; set; }

            private readonly PacketType _requestType;
            public PendingOperation(PacketType request)
            {
                _requestType = request;
                _core.RunContinuationsAsynchronously = true;
            }

            internal void HandleClose(Exception exception)
            {
                _core.SetException(exception);
            }

            internal void HandleReply(SftpClient client, ReadOnlySpan<byte> reply)
            {
                PacketReader reader = new(reply);

                PacketType responseType = reader.ReadPacketType();
                reader.ReadInt(); // id

                SftpError error = SftpError.None;
                if (responseType == PacketType.SSH_FXP_STATUS)
                {
                    error = (SftpError)reader.ReadUInt();
                }

                if (error != SftpError.None && !(_requestType == PacketType.SSH_FXP_READ && error == SftpError.Eof))
                {
                    _core.SetException(new SftpException(error));
                    return;
                }
                switch (_requestType, responseType)
                {
                    case (PacketType.SSH_FXP_OPEN, PacketType.SSH_FXP_HANDLE):
                        string handle = reader.ReadString();
                        _core.SetResult(new SftpFile(client, handle));
                        return;
                    case (PacketType.SSH_FXP_READ, PacketType.SSH_FXP_DATA):
                    case (PacketType.SSH_FXP_READ, PacketType.SSH_FXP_STATUS):
                        (var file, var buffer) = (Context as SftpFile, Buffer);
                        (Context, Buffer) = (default, default);

                        int count;
                        if (error == SftpError.Eof)
                        {
                            count = 0;
                        }
                        else
                        {
                            count = reader.ReadInt();
                            reader.Remainder.Slice(0, count).CopyTo(buffer.Span);
                        }

                        file.CompleteOperation(count);

                        SetIntResult(count);
                        return;
                }
                if (responseType == PacketType.SSH_FXP_STATUS)
                {
                    _core.SetResult(null!);
                }
                else
                {
                    _core.SetException(new SshOperationException($"Cannot handle {responseType} for {_requestType}."));
                }
            }

            public object GetResult(short token) => _core.GetResult(token);

            int IValueTaskSource<int>.GetResult(short token)
            {
                _core.GetResult(token);
                return IntResult;
            }

            public ValueTaskSourceStatus GetStatus(short token) => _core.GetStatus(token);

            public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
                => _core.OnCompleted(continuation, state, token, flags);
        }
    }

    public class SftpException : SshOperationException
    {
        public SftpError Error { get; private set; }

        internal SftpException(SftpError error) : base(error.ToString())
        {
            Error = error;
        }
    }

    public enum SftpError
    {
        None = 0,
        Eof = 1,
        NoSuchFile = 2,
        PermissionDenied = 3,
        Failure = 4,
        BadMessage = 5,
        // NoConnection = 6,
        // ConnectionLost = 7,
        Unsupported = 8
    }

    [Flags]
    public enum OpenFlags : uint
    {
        Read = 1,
        Write = 2,
        Append = 4,
        Open = 0,
        OpenOrCreate = 8,
        TruncateOrCreate = 16 | 32,
        CreateNew = 8 | 32,
    }
}