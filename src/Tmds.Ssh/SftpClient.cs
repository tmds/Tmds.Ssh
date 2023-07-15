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
        private byte[]? _packetBuffer;
        private int _packetBufferLength = 32 * 1024;
        private int _nextId = 5;
        private int GetNextId() => Interlocked.Increment(ref _nextId);

        internal SftpClient(SshChannel channel)
        {
            _channel = channel;
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

        private ValueTask<SftpFile?> OpenFileCoreAsync(string filename, SftpOpenFlags flags, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_OPEN;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(filename);
            packet.WriteUInt((uint)flags);
            packet.WriteAttributes(null);

            return ExecuteAsync<SftpFile?>(packet, id, pendingOperation, cancellationToken);
        }

        public ValueTask DeleteFileAsync(string path, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_REMOVE;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
        }

        public ValueTask DeleteDirectoryAsync(string path, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_RMDIR;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
        }

        public ValueTask RenameAsync(string oldpath, string newpath, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_RENAME;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(oldpath);
            packet.WriteString(newpath);

            return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
        }

        public ValueTask<FileAttributes?> GetAttributesAsync(string path, bool followLinks = true, CancellationToken cancellationToken = default)
        {
            PacketType packetType = followLinks ? PacketType.SSH_FXP_STAT : PacketType.SSH_FXP_LSTAT ;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            return ExecuteAsync<FileAttributes?>(packet, id, pendingOperation, cancellationToken);
        }

        public IAsyncEnumerable<(string Name, FileAttributes Attributes)> GetEntriesAsync(string path)
            => new SftpFileSystemEnumerable<(string, FileAttributes)>(this, path,
                    transform: (ref SftpFileEntry entry) => (new string(entry.FileName), entry.GetAttributes()));

        internal ValueTask<string> OpenDirectoryAsync(string path, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_OPENDIR;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            return ExecuteAsync<string>(packet, id, pendingOperation, cancellationToken);
        }

        public ValueTask CreateDirectoryAsync(string path, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_MKDIR;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);
            packet.WriteAttributes(null);

            return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
        }

        internal async Task ProtocolInitAsync(CancellationToken cancellationToken)
        {
            using Packet packet = new Packet(PacketType.SSH_FXP_INIT);
            packet.WriteUInt(ProtocolVersion);
            await _channel.WriteAsync(packet.Data, cancellationToken);

            ReadOnlyMemory<byte> versionPacket = await ReadPacketAsync(cancellationToken);
            HandleVersionPacket(versionPacket.Span);

            _ = ReadAllPacketsAsync();
            _ = SendPacketsAsync();
        }

        internal ValueTask<byte[]> ReadDirAsync(string handle, CancellationToken cancellationToken)
        {
            PacketType packetType = PacketType.SSH_FXP_READDIR;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);

            return ExecuteAsync<byte[]>(packet, id, pendingOperation, cancellationToken);
        }

        internal byte[] StealPacketBuffer()
        {
            var packetBuffer = _packetBuffer!;
            _packetBuffer = null;
            return packetBuffer;
        }

        private async ValueTask<ReadOnlyMemory<byte>> ReadPacketAsync(CancellationToken cancellationToken = default)
        {
            if (_packetBuffer is null)
            {
                _packetBuffer = new byte[_packetBufferLength]; // TODO: rent from shared pool.
            }
            int totalReceived = 0;

            // Read packet length.
            do
            {
                Memory<byte> readBuffer = new Memory<byte>(_packetBuffer, totalReceived, 4 - totalReceived);
                (ChannelReadType type, int bytesRead) = await _channel.ReadAsync(readBuffer, default, cancellationToken);
                if (type != ChannelReadType.StandardOutput)
                {
                    return default;
                }
                totalReceived += bytesRead;
            } while (totalReceived < 4);

            int packetLength = BinaryPrimitives.ReadInt32BigEndian(_packetBuffer);
            int totalReceiveLength = packetLength + 4;

            // Ensure receive buffer can fit packet.
            if (_packetBuffer!.Length < totalReceiveLength)
            {
                _packetBufferLength = totalReceiveLength;
                _packetBuffer = new byte[totalReceiveLength];
                BinaryPrimitives.WriteInt32BigEndian(_packetBuffer, packetLength);
            }

            // Read packet.
            while (totalReceived < totalReceiveLength)
            {
                Memory<byte> readBuffer = new Memory<byte>(_packetBuffer, totalReceived, _packetBuffer.Length - totalReceived);
                (ChannelReadType type, int bytesRead) = await _channel.ReadAsync(readBuffer, default, cancellationToken);
                if (type != ChannelReadType.StandardOutput)
                {
                    return default;
                }
                totalReceived += bytesRead;
            }
            return new ReadOnlyMemory<byte>(_packetBuffer, 4, packetLength);
        }

        private async Task SendPacketsAsync()
        {
            bool sendPackets = true;
            await foreach (Packet packet in _pendingSends.Reader.ReadAllAsync())
            {
                if (sendPackets)
                {
                    try
                    {
                        await _channel.WriteAsync(packet.Data);
                    }
                    catch
                    {
                        sendPackets = false;
                    }
                }
                packet.Dispose();
            }
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
                // Ensure the channel is closed
                // and CreatePendingOperationCloseException will return an appropriate exception.
                _channel.Cancel();

                // No additional sends can be queued.
                _pendingSends.Writer.Complete();

                // Complete pending operations.
                foreach (var item in _pendingOperations)
                {
                    if (_pendingOperations.TryRemove(item.Key, out PendingOperation? removed))
                    {
                        removed.HandleClose();
                    }
                }
            }
        }

        internal Exception CreatePendingOperationCloseException()
        {
            return _channel.CreateCloseException(
                createCancelException: () => new SshOperationException("Unexpected reply or eof."));
        }

        private void HandleVersionPacket(ReadOnlySpan<byte> packet)
        {
            PacketType type = (PacketType)packet[0];
            if (type != PacketType.SSH_FXP_VERSION)
            {
                throw new SshOperationException($"Expected packet SSH_FXP_VERSION, but received {type}.");
            }
        }

        internal ValueTask<int> ReadFileAsync(string handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken)
        {
            PacketType packetType = PacketType.SSH_FXP_READ;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);
            pendingOperation.Buffer = buffer;

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);
            packet.WriteInt64(offset);
            packet.WriteInt(buffer.Length);

            return ExecuteAsync<int>(packet, id, pendingOperation, cancellationToken);
        }

        internal ValueTask<FileAttributes> GetAttributesForHandleAsync(string handle, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_FSTAT;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);

            return ExecuteAsync<FileAttributes>(packet, id, pendingOperation, cancellationToken);
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

                Packet packet = new Packet(packetType, payloadSize:
                                                                4 /* id */
                                                                + Packet.MaxHandleStringLength
                                                                + 8 /* offset */
                                                                + Packet.GetStringLength(writeBuffer.Span));
                packet.WriteInt(id);
                packet.WriteString(handle);
                packet.WriteInt64(offset);
                packet.WriteString(writeBuffer);

                await ExecuteAsync(packet, id, pendingOperation, cancellationToken);

                buffer = buffer.Slice(writeLength);
                offset += writeLength;
            }
        }

        internal void CloseFile(string handle)
        {
            _ = CloseFileAsync(handle, default(CancellationToken));
        }

        internal ValueTask CloseFileAsync(string handle, CancellationToken cancellationToken)
        {
            PacketType packetType = PacketType.SSH_FXP_CLOSE;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);

            return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
        }
    }
}