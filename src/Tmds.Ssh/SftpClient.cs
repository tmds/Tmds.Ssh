// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO;

namespace Tmds.Ssh
{
    public sealed partial class SftpClient : IDisposable
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
        const uint ProtocolVersion = 3;

        private readonly SshChannel _channel;
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

        public ValueTask<SftpFile> OpenOrCreateFileAsync(string filename, FileAccess access, CancellationToken cancellationToken = default)
            => OpenOrCreateFileAsync(filename, access, OpenMode.None, cancellationToken);

        public async ValueTask<SftpFile> OpenOrCreateFileAsync(string filename, FileAccess access, OpenMode mode, CancellationToken cancellationToken = default)
            => await OpenFileCoreAsync(filename, GetOpenFlags(SftpOpenFlags.OpenOrCreate, access, mode), cancellationToken)
                ?? throw new SftpException(SftpError.NoSuchFile);

        public ValueTask<SftpFile> CreateNewFileAsync(string filename, FileAccess access, CancellationToken cancellationToken = default)
            => CreateNewFileAsync(filename, access, OpenMode.None, cancellationToken);

        public async ValueTask<SftpFile> CreateNewFileAsync(string filename, FileAccess access, OpenMode mode, CancellationToken cancellationToken = default)
            => await OpenFileCoreAsync(filename, GetOpenFlags(SftpOpenFlags.CreateNew, access, mode), cancellationToken)
                ?? throw new SftpException(SftpError.NoSuchFile);

        public ValueTask<SftpFile?> OpenFileAsync(string filename, FileAccess access, CancellationToken cancellationToken = default)
            => OpenFileAsync(filename, access, OpenMode.None, cancellationToken);

        public async ValueTask<SftpFile?> OpenFileAsync(string filename, FileAccess access, OpenMode mode, CancellationToken cancellationToken = default)
            => await OpenFileCoreAsync(filename, GetOpenFlags(SftpOpenFlags.Open, access, mode), cancellationToken);

        private SftpOpenFlags GetOpenFlags(SftpOpenFlags flags, FileAccess access, OpenMode mode)
        {
            if ((mode & OpenMode.Truncate) != 0)
            {
                flags |= SftpOpenFlags.Truncate;
            }
            if ((mode & OpenMode.Append) != 0)
            {
                flags |= SftpOpenFlags.Append;
            }
            flags |= (SftpOpenFlags)(access & FileAccess.ReadWrite);
            return flags;
        }

        private async ValueTask<SftpFile?> OpenFileCoreAsync(string filename, SftpOpenFlags flags, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_OPEN;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(filename);
            packet.WriteUInt((uint)flags);
            packet.WriteAttributes(null);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation, cancellationToken);

            return (SftpFile?)await new ValueTask<object?>(pendingOperation, pendingOperation.Token);
        }

        public async ValueTask DeleteFileAsync(string path, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_REMOVE;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation, cancellationToken);

            await new ValueTask<object?>(pendingOperation, pendingOperation.Token);
        }

        public async ValueTask DeleteDirectoryAsync(string path, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_RMDIR;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation, cancellationToken);

            await new ValueTask<object?>(pendingOperation, pendingOperation.Token);
        }

        public async ValueTask RenameAsync(string oldpath, string newpath, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_RENAME;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(oldpath);
            packet.WriteString(newpath);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation, cancellationToken);

            await new ValueTask<object?>(pendingOperation, pendingOperation.Token);
        }

        public async ValueTask<FileAttributes?> GetAttributesAsync(string path, bool followLinks = true, CancellationToken cancellationToken = default)
        {
            PacketType packetType = followLinks ? PacketType.SSH_FXP_STAT : PacketType.SSH_FXP_LSTAT ;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation, cancellationToken);

            return (FileAttributes?)await new ValueTask<object?>(pendingOperation, pendingOperation.Token);
        }

        public async ValueTask CreateDirectoryAsync(string path, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_MKDIR;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);
            packet.WriteAttributes(null);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation, cancellationToken);

            await new ValueTask<object?>(pendingOperation, pendingOperation.Token);
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
                    if (_pendingOperations.Remove(id, out PendingOperation? operation))
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
                _channel.Cancel();

                _writeSemaphore.Wait();

                foreach (var item in _pendingOperations)
                {
                    var exception = _channel.CreateCloseException(
                                        // Override the cancellation exception.
                                        createCancelException: () => new SshOperationException("Unexpected reply or eof."));
                    item.Value.HandleClose(exception);
                }
                _pendingOperations.Clear();

                _writeSemaphore.Release();
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

        internal async ValueTask<int> ReadFileAsync(string handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken)
        {
            PacketType packetType = PacketType.SSH_FXP_READ;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);
            pendingOperation.Buffer = buffer;

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);
            packet.WriteInt64(offset);
            packet.WriteInt(buffer.Length);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation, cancellationToken);

            return await new ValueTask<int>(pendingOperation, pendingOperation.Token);
        }

        internal async ValueTask<FileAttributes> GetAttributesForHandleAsync(string handle, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_FSTAT;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation, cancellationToken);

            return (FileAttributes)(await new ValueTask<object?>(pendingOperation, pendingOperation.Token))!;
        }

        internal async ValueTask WriteFileAsync(string handle, long offset, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
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
                PendingOperation pendingOperation = CreatePendingOperation(packetType);
                pendingOperation.Buffer = MemoryMarshal.AsMemory(writeBuffer);

                using Packet packet = new Packet(packetType, payloadSize:
                                                                4 /* id */
                                                                + Packet.MaxHandleStringLength
                                                                + 8 /* offset */
                                                                + Packet.GetStringLength(writeBuffer.Span));
                packet.WriteInt(id);
                packet.WriteString(handle);
                packet.WriteInt64(offset);
                packet.WriteString(writeBuffer);

                await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation, cancellationToken);

                await new ValueTask<object?>(pendingOperation, pendingOperation.Token);

                buffer = buffer.Slice(writeLength);
                offset += writeLength;
            }
        }

        internal void CloseFile(string handle)
        {
            _ = CloseFileAsync(handle, default(CancellationToken));
        }

        internal async ValueTask CloseFileAsync(string handle, CancellationToken cancellationToken)
        {
            PacketType packetType = PacketType.SSH_FXP_CLOSE;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            using Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);

            await WritePacketForPendingOperationAsync(packet, packetType, id, pendingOperation, cancellationToken);

            await new ValueTask<object?>(pendingOperation, pendingOperation.Token);
        }
    }
}