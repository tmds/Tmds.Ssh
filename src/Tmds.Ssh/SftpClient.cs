// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;
using System.Buffers;
using System.IO.Enumeration;
using System.Text;

namespace Tmds.Ssh
{
    public sealed partial class SftpClient : IDisposable
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
        const uint ProtocolVersion = 3;

        private static readonly EnumerationOptions DefaultEnumerationOptions = new();

        private readonly SshChannel _channel;
        private byte[]? _packetBuffer;
        private int _nextId = 5;
        private int GetNextId() => Interlocked.Increment(ref _nextId);

        internal SftpClient(SshChannel channel)
        {
            _channel = channel;
        }

        internal int GetMaxWritePayload(byte[] handle) // SSH_FXP_WRITE payload
            => _channel.SendMaxPacket
                - 4 /* packet length */ - 1 /* packet type */ - 4 /* id */
                - 4 /* handle length */ - handle.Length - 8 /* offset */ - 4 /* data length */;

        internal int MaxReadPayload // SSH_FXP_DATA payload
            => _channel.ReceiveMaxPacket
                - 4 /* packet length */ - 1 /* packet type */ - 4 /* id */ - 4 /* payload length */;

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
            PacketType packetType = followLinks ? PacketType.SSH_FXP_STAT : PacketType.SSH_FXP_LSTAT;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            return ExecuteAsync<FileAttributes?>(packet, id, pendingOperation, cancellationToken);
        }

        public IAsyncEnumerable<(string Path, FileAttributes Attributes)> GetDirectoryEntriesAsync(string path, EnumerationOptions? options = null)
            => GetDirectoryEntriesAsync<(string, FileAttributes)>(path, (ref SftpFileEntry entry) => (entry.ToPath(), entry.ToAttributes()), options);

        public IAsyncEnumerable<T> GetDirectoryEntriesAsync<T>(string path, SftpFileEntryTransform<T> transform, EnumerationOptions? options = null)
            => new SftpFileSystemEnumerable<T>(this, path, transform, options ?? DefaultEnumerationOptions);

        internal ValueTask<byte[]> OpenDirectoryAsync(string path, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_OPENDIR;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            return ExecuteAsync<byte[]>(packet, id, pendingOperation, cancellationToken);
        }

        public ValueTask CreateDirectoryAsync(string path, CancellationToken cancellationToken = default)
            => CreateDirectoryAsync(path, createParents: false, cancellationToken);

        public async ValueTask CreateDirectoryAsync(string path, bool createParents, CancellationToken cancellationToken = default)
        {
            // This method doesn't throw if the target directory already exists.
            // We run a SSH_FXP_STAT in parallel with the SSH_FXP_MKDIR to check if the target directory already exists.
            ValueTask<FileAttributes?> checkExists = GetAttributesAsync(path, followLinks: true /* allow the path to be a link to a dir */, cancellationToken);
            ValueTask mkdir = CreateNewDirectoryAsync(path, createParents, cancellationToken);

            try
            {
                await mkdir;
                await IsDirectory(checkExists);
            }
            catch (SftpException ex) when (ex.Error == SftpError.Failure)
            {
                if (await IsDirectory(checkExists))
                {
                    return;
                }

                throw;
            }

            async ValueTask<bool> IsDirectory(ValueTask<FileAttributes?> checkExists)
            {
                try
                {
                    FileAttributes? attributes = await checkExists;
                    return attributes?.FileType == UnixFileType.Directory;
                }
                catch
                {
                    return false;
                }
            }
        }

        public ValueTask CreateNewDirectoryAsync(string path, CancellationToken cancellationToken = default)
            => CreateNewDirectoryAsync(path, createParents: false, cancellationToken);

        public ValueTask CreateNewDirectoryAsync(string path, bool createParents, CancellationToken cancellationToken = default)
        {
            if (createParents)
            {
                ReadOnlySpan<char> span = RemotePath.TrimEndingDirectorySeparator(path);
                int offset = 1;
                int idx = 0;
                while ((idx = span.Slice(offset).IndexOf(RemotePath.DirectorySeparatorChar)) != -1)
                {
                    offset += idx;
                    _ = CreateNewDirectoryAsync(span.Slice(0, offset), awaitable: false);
                    offset++;
                }
            }

            return CreateNewDirectoryAsync(path.AsSpan(), awaitable: true, cancellationToken);
        }

        public async ValueTask UploadDirectoryEntriesAsync(string localDirectory, string remoteDirectory, bool overwrite, CancellationToken cancellationToken = default)
        {
            localDirectory = Path.GetFullPath(localDirectory);
            int trimLocalDirectory = localDirectory.Length;
            if (!LocalPath.EndsInDirectorySeparator(localDirectory))
            {
                trimLocalDirectory++;
            }
            remoteDirectory = RemotePath.EnsureTrailingSeparator(remoteDirectory);

            char[] pathBuffer = ArrayPool<char>.Shared.Rent(RemotePath.MaxPathLength);
            var fse = new FileSystemEnumerable<(string LocalPath, string RemotePath, UnixFileType Type, long Length)>(localDirectory,
                            (ref FileSystemEntry entry) =>
                            {
                                string localPath = entry.ToFullPath();
                                using ValueStringBuilder remotePathBuilder = new(pathBuffer);
                                remotePathBuilder.Append(remoteDirectory);
                                remotePathBuilder.AppendLocalPathToRemotePath(localPath.AsSpan(trimLocalDirectory));
                                var attributes = entry.Attributes;
                                UnixFileType mode = (attributes & System.IO.FileAttributes.ReparsePoint) != 0 ? UnixFileType.SymbolicLink :
                                                    (attributes & System.IO.FileAttributes.Directory) != 0    ? UnixFileType.Directory :
                                                                                                                UnixFileType.RegularFile;
                                long length = entry.Length;
                                return (localPath, remotePathBuilder.ToString(), mode, length);
                            },
                            new System.IO.EnumerationOptions()
                            {
                                RecurseSubdirectories = true
                            });

            byte[] buffer = ArrayPool<byte>.Shared.Rent(_channel.SendMaxPacket);
            try
            {
                foreach (var item in fse)
                {
                    switch (item.Type)
                    {
                        case UnixFileType.Directory:
                            if (overwrite)
                            {
                                await CreateDirectoryAsync(item.RemotePath, cancellationToken);
                            }
                            else
                            {
                                await CreateNewDirectoryAsync(item.RemotePath, cancellationToken);
                            }
                            break;
                        case UnixFileType.RegularFile:
                            {
                                using SftpFile remoteFile = overwrite ? await OpenOrCreateFileAsync(item.RemotePath, FileAccess.Write, OpenMode.Truncate, cancellationToken)
                                                                      : await CreateNewFileAsync(item.RemotePath, FileAccess.Write, cancellationToken);

                                using FileStream localFile = new FileStream(item.LocalPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 0);
                                int bytesRead;
                                do
                                {
                                    bytesRead = localFile.Read(buffer.AsSpan(0, GetMaxWritePayload(remoteFile.Handle)));
                                    if (bytesRead != 0)
                                    {
                                        await remoteFile.WriteAsync(buffer.AsMemory(0, bytesRead));
                                    }
                                } while (bytesRead != 0);
                            }
                            break;
                        case UnixFileType.SymbolicLink:
                            throw new NotImplementedException($"{item.Type}"); // TODO
                        default:
                            break;
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                ArrayPool<char>.Shared.Return(pathBuffer);
            }
        }

        public async ValueTask DownloadDirectoryEntriesAsync(string remoteDirectory, string localDirectory, bool overwrite, CancellationToken cancellationToken = default)
        {
            int trimRemoteDirectory = remoteDirectory.Length;
            if (!LocalPath.EndsInDirectorySeparator(remoteDirectory))
            {
                trimRemoteDirectory++;
            }
            localDirectory = LocalPath.EnsureTrailingSeparator(localDirectory);

            char[] pathBuffer = ArrayPool<char>.Shared.Rent(4096);
            var fse = GetDirectoryEntriesAsync<(string LocalPath, string RemotePath, UnixFileType Type, long Length)>(remoteDirectory,
                (ref SftpFileEntry entry) =>
                {
                    string remotePath = entry.ToPath();
                    using ValueStringBuilder localPathBuilder = new(pathBuffer);
                    localPathBuilder.Append(localDirectory);
                    localPathBuilder.Append(remotePath.Substring(trimRemoteDirectory));
                    return (localPathBuilder.ToString(), remotePath, entry.FileType, entry.Length);
                },
                new EnumerationOptions() { RecurseSubdirectories = true });

            byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxReadPayload);
            try
            {
                await foreach (var item in fse.WithCancellation(cancellationToken))
                {
                    switch (item.Type)
                    {
                        case UnixFileType.Directory:
                            bool exists = Directory.Exists(item.LocalPath);
                            if (!overwrite && exists)
                            {
                                throw new IOException($"Directory '{item.LocalPath}' already exists.");
                            }
                            if (!exists)
                            {
                                Directory.CreateDirectory(item.LocalPath);
                            }
                            break;
                        case UnixFileType.RegularFile:
                            {
                                using SftpFile? remoteFile = await OpenFileAsync(item.RemotePath, FileAccess.Read, cancellationToken);
                                if (remoteFile is null)
                                {
                                    continue;
                                }

                                using FileStream localFile = new FileStream(item.LocalPath, overwrite ? FileMode.Create : FileMode.CreateNew,
                                    FileAccess.Write, FileShare.None, bufferSize: 0);

                                int bytesRead;
                                do
                                {
                                    bytesRead = await remoteFile.ReadAsync(buffer, cancellationToken);
                                    if (bytesRead != 0)
                                    {
                                        localFile.Write(buffer.AsSpan(0, bytesRead));
                                    }
                                } while (bytesRead != 0);
                            }
                            break;
                        case UnixFileType.SymbolicLink:
                            throw new NotImplementedException($"{item.Type}"); // TODO
                        default:
                            break;
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                ArrayPool<char>.Shared.Return(pathBuffer);
            }
        }

        private ValueTask CreateNewDirectoryAsync(ReadOnlySpan<char> path, bool awaitable, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_MKDIR;

            int id = GetNextId();
            PendingOperation? pendingOperation = awaitable ? CreatePendingOperation(packetType) : null;

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

        internal ValueTask<byte[]> ReadDirAsync(byte[] handle, CancellationToken cancellationToken)
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
                _packetBuffer = new byte[_channel.ReceiveMaxPacket]; // TODO: rent from shared pool.
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

            // Read packet.
            while (totalReceived < totalReceiveLength)
            {
                Memory<byte> readBuffer = new Memory<byte>(_packetBuffer, totalReceived, totalReceiveLength - totalReceived);
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

        internal ValueTask<int> ReadFileAsync(byte[] handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken)
        {
            PacketType packetType = PacketType.SSH_FXP_READ;

            if (buffer.Length > MaxReadPayload)
            {
                buffer = buffer.Slice(0, MaxReadPayload);
            }

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

        internal ValueTask<FileAttributes> GetAttributesForHandleAsync(byte[] handle, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_FSTAT;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);

            return ExecuteAsync<FileAttributes>(packet, id, pendingOperation, cancellationToken);
        }

        internal ValueTask WriteFileAsync(byte[] handle, long offset, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            if (buffer.Length <= GetMaxWritePayload(handle))
            {
                return WriteFileSingleAsync(handle, offset, buffer, cancellationToken);
            }
            else
            {
                return WriteFileMultiAsync(handle, offset, buffer, cancellationToken);
            }
        }

        private async ValueTask WriteFileMultiAsync(byte[] handle, long offset, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            while (!buffer.IsEmpty)
            {
                int writeLength = Math.Min(buffer.Length, GetMaxWritePayload(handle));

                await WriteFileSingleAsync(handle, offset, buffer.Slice(0, writeLength), cancellationToken);

                buffer = buffer.Slice(writeLength);
                offset += writeLength;
            }
        }

        internal ValueTask WriteFileSingleAsync(byte[] handle, long offset, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            Debug.Assert(buffer.Length <= GetMaxWritePayload(handle));

            PacketType packetType = PacketType.SSH_FXP_WRITE;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);
            pendingOperation.Buffer = MemoryMarshal.AsMemory(buffer);

            Packet packet = new Packet(packetType, payloadSize:
                                                            4   /* id */
                                                            + Packet.GetStringLength(handle)
                                                            + 8 /* offset */
                                                            + Packet.GetStringLength(buffer.Span));
            packet.WriteInt(id);
            packet.WriteString(handle);
            packet.WriteInt64(offset);
            packet.WriteString(buffer);

            return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
        }

        internal void CloseFile(byte[] handle)
        {
            PacketType packetType = PacketType.SSH_FXP_CLOSE;

            int id = GetNextId();

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);

            _ = ExecuteAsync(packet, id, pendingOperation: null, cancellationToken: default);
        }

        internal ValueTask CloseFileAsync(byte[] handle, CancellationToken cancellationToken)
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