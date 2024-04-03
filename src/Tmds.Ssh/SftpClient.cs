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
using Microsoft.Win32.SafeHandles;

namespace Tmds.Ssh
{
    public sealed partial class SftpClient : IDisposable
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
        const uint ProtocolVersion = 3;

        const int MaxConcurrentOperations = 64;
        // Limit the number of buffers allocated for copying.
        // An onGoing ValueTask may allocate multiple buffers.
        const int MaxConcurrentBuffers = 64;

        const UnixFilePermissions OwnershipPermissions =
                UnixFilePermissions.UserRead | UnixFilePermissions.UserWrite | UnixFilePermissions.UserExecute |
                UnixFilePermissions.GroupRead | UnixFilePermissions.GroupWrite | UnixFilePermissions.GroupExecute |
                UnixFilePermissions.OtherRead | UnixFilePermissions.OtherWrite | UnixFilePermissions.OtherExecute;
        const UnixFilePermissions DefaultCreateDirectoryPermissions = OwnershipPermissions;
        const UnixFilePermissions DefaultCreateFilePermissions =
                UnixFilePermissions.UserRead | UnixFilePermissions.UserWrite |
                UnixFilePermissions.GroupRead | UnixFilePermissions.GroupWrite |
                UnixFilePermissions.OtherRead | UnixFilePermissions.OtherWrite;
        const UnixFilePermissions CreateFilePermissionMask = OwnershipPermissions;
        const UnixFilePermissions CreateDirectoryPermissionMask = OwnershipPermissions | UnixFilePermissions.StickyBit;
        const UnixFilePermissions PretendUMask = UnixFilePermissions.OtherWrite;

        private static readonly EnumerationOptions DefaultEnumerationOptions = new();
        private static readonly UploadEntriesOptions DefaultUploadEntriesOptions = new();
        private static readonly DownloadEntriesOptions DefaultDownloadEntriesOptions = new();

        private readonly SshChannel _channel;

        // Limits the number of buffers concurrently used for uploading/downloading.
        private readonly SemaphoreSlim s_downloadBufferSemaphore = new SemaphoreSlim(MaxConcurrentBuffers, MaxConcurrentBuffers);
        private readonly SemaphoreSlim s_uploadBufferSemaphore = new SemaphoreSlim(MaxConcurrentBuffers, MaxConcurrentBuffers);

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

        public ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
            => OpenOrCreateFileAsync(path, access, OpenMode.None, cancellationToken);

        public async ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, OpenMode mode, CancellationToken cancellationToken = default)
            => await OpenFileCoreAsync(path, GetOpenFlags(SftpOpenFlags.OpenOrCreate, access, mode), permissions: DefaultCreateFilePermissions, cancellationToken)
                ?? throw new SftpException(SftpError.NoSuchFile);

        public ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
            => CreateNewFileAsync(path, access, OpenMode.None, cancellationToken);

        public async ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, OpenMode mode, CancellationToken cancellationToken = default)
            => await OpenFileCoreAsync(path, GetOpenFlags(SftpOpenFlags.CreateNew, access, mode), permissions: DefaultCreateFilePermissions, cancellationToken)
                ?? throw new SftpException(SftpError.NoSuchFile);

        public ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, UnixFilePermissions createPermissions, CancellationToken cancellationToken = default)
            => OpenOrCreateFileAsync(path, access, OpenMode.None, createPermissions, cancellationToken);

        public async ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, OpenMode mode, UnixFilePermissions createPermissions, CancellationToken cancellationToken = default)
            => await OpenFileCoreAsync(path, GetOpenFlags(SftpOpenFlags.OpenOrCreate, access, mode), createPermissions, cancellationToken)
                ?? throw new SftpException(SftpError.NoSuchFile);

        public ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, UnixFilePermissions permissions, CancellationToken cancellationToken = default)
            => CreateNewFileAsync(path, access, OpenMode.None, permissions, cancellationToken);

        public async ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, OpenMode mode, UnixFilePermissions permissions, CancellationToken cancellationToken = default)
            => await OpenFileCoreAsync(path, GetOpenFlags(SftpOpenFlags.CreateNew, access, mode), permissions, cancellationToken)
                ?? throw new SftpException(SftpError.NoSuchFile);

        public ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
            => OpenFileAsync(path, access, OpenMode.None, cancellationToken);

        public async ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, OpenMode mode, CancellationToken cancellationToken = default)
            => await OpenFileCoreAsync(path, GetOpenFlags(SftpOpenFlags.Open, access, mode), permissions: DefaultCreateFilePermissions, cancellationToken);

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

        private ValueTask<SftpFile?> OpenFileCoreAsync(string path, SftpOpenFlags flags, UnixFilePermissions permissions, CancellationToken cancellationToken)
        {
            PacketType packetType = PacketType.SSH_FXP_OPEN;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);
            packet.WriteUInt((uint)flags);
            packet.WriteAttributes(permissions: permissions & CreateFilePermissionMask, fileType: UnixFileType.RegularFile);

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

        public ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_RENAME;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(oldPath);
            packet.WriteString(newPath);

            return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
        }

        public ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, bool followLinks = true, CancellationToken cancellationToken = default)
        {
            PacketType packetType = followLinks ? PacketType.SSH_FXP_STAT : PacketType.SSH_FXP_LSTAT;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            return ExecuteAsync<FileEntryAttributes?>(packet, id, pendingOperation, cancellationToken);
        }

        public ValueTask<string> GetLinkTargetAsync(string linkPath, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_READLINK;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(linkPath);

            return ExecuteAsync<string>(packet, id, pendingOperation, cancellationToken);
        }

        public ValueTask<string> GetFullPathAsync(string path, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_REALPATH;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);

            return ExecuteAsync<string>(packet, id, pendingOperation, cancellationToken);
        }

        public ValueTask CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default)
            => CreateSymbolicLinkAsync(linkPath, targetPath, overwrite: false, cancellationToken);

        private ValueTask CreateSymbolicLinkAsync(string linkPath, string targetPath, bool overwrite, CancellationToken cancellationToken)
        {
            int id;
            Packet packet;

            if (overwrite)
            {
                id = GetNextId();

                packet = new Packet(PacketType.SSH_FXP_REMOVE);
                packet.WriteInt(id);
                packet.WriteString(linkPath);

                _ = ExecuteAsync(packet, id, pendingOperation: null, cancellationToken: default);
            }

            PacketType packetType = PacketType.SSH_FXP_SYMLINK;

            id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            packet = new Packet(packetType);
            packet.WriteInt(id);
            // ... OpenSSH has these arguments swapped: https://bugzilla.mindrot.org/show_bug.cgi?id=861
            packet.WriteString(targetPath);
            packet.WriteString(linkPath);

            return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
        }

        public IAsyncEnumerable<(string Path, FileEntryAttributes Attributes)> GetDirectoryEntriesAsync(string path, EnumerationOptions? options = null)
            => GetDirectoryEntriesAsync<(string, FileEntryAttributes)>(path, (ref SftpFileEntry entry) => (entry.ToPath(), entry.ToAttributes()), options);

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

        public ValueTask CreateDirectoryAsync(string path, bool createParents, CancellationToken cancellationToken = default)
            => CreateDirectoryAsync(path, createParents, permissions: DefaultCreateDirectoryPermissions, cancellationToken);

        public ValueTask CreateDirectoryAsync(string path, UnixFilePermissions createPermissions, CancellationToken cancellationToken = default)
            => CreateDirectoryAsync(path, createParents: false, createPermissions, cancellationToken);

        public async ValueTask CreateDirectoryAsync(string path, bool createParents, UnixFilePermissions permissions, CancellationToken cancellationToken = default)
        {
            // This method doesn't throw if the target directory already exists.
            // We run a SSH_FXP_STAT in parallel with the SSH_FXP_MKDIR to check if the target directory already exists.
            ValueTask<FileEntryAttributes?> checkExists = GetAttributesAsync(path, followLinks: true /* allow the path to be a link to a dir */, cancellationToken);
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

            async ValueTask<bool> IsDirectory(ValueTask<FileEntryAttributes?> checkExists)
            {
                try
                {
                    FileEntryAttributes? attributes = await checkExists;
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

        public ValueTask CreateNewDirectoryAsync(string path, UnixFilePermissions permissions, CancellationToken cancellationToken = default)
            => CreateNewDirectoryAsync(path, createParents: false, permissions, cancellationToken);

        public ValueTask CreateNewDirectoryAsync(string path, bool createParents, CancellationToken cancellationToken = default)
            => CreateNewDirectoryAsync(path, createParents, permissions: DefaultCreateDirectoryPermissions, cancellationToken);

        public ValueTask CreateNewDirectoryAsync(string path, bool createParents, UnixFilePermissions permissions, CancellationToken cancellationToken = default)
        {
            if (createParents)
            {
                ReadOnlySpan<char> span = RemotePath.TrimEndingDirectorySeparators(path);
                int offset = 1;
                int idx = 0;
                while ((idx = span.Slice(offset).IndexOf(RemotePath.DirectorySeparatorChar)) != -1)
                {
                    offset += idx;
                    // note: parent directories are created using the default permissions, not the permissions arg.
                    _ = CreateNewDirectoryAsync(span.Slice(0, offset), awaitable: false, permissions: DefaultCreateDirectoryPermissions, cancellationToken: default);
                    offset++;
                }
            }

            return CreateNewDirectoryAsync(path.AsSpan(), awaitable: true, permissions, cancellationToken);
        }

        public ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, CancellationToken cancellationToken = default)
            => UploadDirectoryEntriesAsync(localDirPath, remoteDirPath, options: null, cancellationToken);

        public async ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, UploadEntriesOptions? options, CancellationToken cancellationToken = default)
        {
            options ??= DefaultUploadEntriesOptions;
            bool overwrite = options.Overwrite;
            bool recurse = options.RecurseSubdirectories;

            localDirPath = Path.GetFullPath(localDirPath);
            int trimLocalDirectory = localDirPath.Length;
            if (!LocalPath.EndsInDirectorySeparator(localDirPath))
            {
                trimLocalDirectory++;
            }
            remoteDirPath = RemotePath.EnsureTrailingSeparator(remoteDirPath);

            bool followFileLinks = options.FollowFileLinks;
            bool followDirectoryLinks = options.FollowDirectoryLinks;

            char[] pathBuffer = ArrayPool<char>.Shared.Rent(RemotePath.MaxPathLength);
            var fse = new FileSystemEnumerable<(string LocalPath, string RemotePath, UnixFileType Type, long Length)>(localDirPath,
                            (ref FileSystemEntry entry) =>
                            {
                                string localPath = entry.ToFullPath();
                                using ValueStringBuilder remotePathBuilder = new(pathBuffer);
                                remotePathBuilder.Append(remoteDirPath);
                                remotePathBuilder.AppendLocalPathToRemotePath(localPath.AsSpan(trimLocalDirectory));
                                var attributes = entry.Attributes;
                                bool isLink = (attributes & FileAttributes.ReparsePoint) != 0;
                                UnixFileType type;
                                if ((attributes & FileAttributes.Directory) != 0)
                                {
                                    type = (isLink && !followDirectoryLinks) ? UnixFileType.SymbolicLink
                                                                             : UnixFileType.Directory;
                                }
                                else
                                {
                                    type = isLink ? UnixFileType.SymbolicLink
                                                  : UnixFileType.RegularFile;
                                }

                                long length = entry.Length;
                                return (localPath, remotePathBuilder.ToString(), type, length);
                            },
                            new System.IO.EnumerationOptions()
                            {
                                RecurseSubdirectories = recurse
                            });

            var onGoing = new Queue<ValueTask>();
            var bufferSemaphore = new SemaphoreSlim(MaxConcurrentBuffers, MaxConcurrentBuffers);
            try
            {
                foreach (var item in fse)
                {
                    if (onGoing.Count == MaxConcurrentOperations)
                    {
                        await onGoing.Dequeue();
                    }
                    switch (item.Type)
                    {
                        case UnixFileType.Directory:
                            if (overwrite)
                            {
                                onGoing.Enqueue(CreateDirectoryAsync(item.RemotePath, createParents: false, GetPermissionsForDirectory(item.LocalPath), cancellationToken));
                            }
                            else
                            {
                                onGoing.Enqueue(CreateNewDirectoryAsync(item.RemotePath, createParents: false, GetPermissionsForDirectory(item.LocalPath), cancellationToken));
                            }
                            break;
                        case UnixFileType.RegularFile:
                            onGoing.Enqueue(UploadFileAsync(item.LocalPath, item.RemotePath, item.Length, overwrite, permissions: null, cancellationToken));
                            break;
                        case UnixFileType.SymbolicLink:
                            FileInfo file = new FileInfo(item.LocalPath);
                            if (followFileLinks &&
                                file.ResolveLinkTarget(returnFinalTarget: true)?.Exists == true)
                            {
                                onGoing.Enqueue(UploadFileAsync(item.LocalPath, item.RemotePath, item.Length, overwrite, permissions: null, cancellationToken));
                            }
                            else
                            {
                                string? targetPath = file.LinkTarget;
                                if (targetPath is null)
                                {
                                    throw new IOException($"Can not determine link target path of '{item.LocalPath}'.");
                                }
                                if (OperatingSystem.IsWindows())
                                {
                                    targetPath = targetPath.Replace('\\', '/');
                                }
                                onGoing.Enqueue(CreateSymbolicLinkAsync(item.RemotePath, targetPath, overwrite, cancellationToken));
                            }
                            break;
                        default:
                            break;
                    }
                }
                while (onGoing.TryDequeue(out ValueTask pending))
                {
                    await pending;
                }
            }
            finally
            {
                while (onGoing.TryDequeue(out ValueTask pending))
                {
                    try
                    {
                        await pending;
                    }
                    catch
                    { }
                }
                ArrayPool<char>.Shared.Return(pathBuffer);
            }
        }

        public ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, CancellationToken cancellationToken = default)
            => UploadFileAsync(localFilePath, remoteFilePath, overwrite: false, cancellationToken);

        public ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite, CancellationToken cancellationToken = default)
            => UploadFileAsync(localFilePath, remoteFilePath, length: null, overwrite, permissions: null, cancellationToken);

        public ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, UnixFilePermissions permissions, CancellationToken cancellationToken = default)
            => UploadFileAsync(localFilePath, remoteFilePath, overwrite: false, permissions, cancellationToken);

        public ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite, UnixFilePermissions createPermissions, CancellationToken cancellationToken = default)
            => UploadFileAsync(localFilePath, remoteFilePath, length: null, overwrite, createPermissions, cancellationToken);

        private static UnixFilePermissions GetPermissionsForDirectory(string directoryPath)
        {
            const UnixFilePermissions Default = DefaultCreateDirectoryPermissions & ~PretendUMask;
#if NET7_0_OR_GREATER
            if (!OperatingSystem.IsWindows())
            {
                return File.GetUnixFileMode(directoryPath).ToUnixFilePermissions();
            }
            return Default; // TODO: do something better on Windows?
#else
            return Default;
#endif
        }

        private static UnixFilePermissions GetPermissionsForFile(SafeFileHandle fileHandle)
        {
            const UnixFilePermissions Default = DefaultCreateFilePermissions & ~PretendUMask;
#if NET7_0_OR_GREATER
            if (!OperatingSystem.IsWindows())
            {
                return File.GetUnixFileMode(fileHandle).ToUnixFilePermissions();
            }
            return Default; // TODO: do something better on Windows?
#else
            return Default;
#endif
        }

        private async ValueTask UploadFileAsync(string localPath, string remotePath, long? length, bool overwrite, UnixFilePermissions? permissions, CancellationToken cancellationToken)
        {
            using SafeFileHandle localFile = File.OpenHandle(localPath, FileMode.Open, FileAccess.Read, FileShare.Read);

            permissions ??= GetPermissionsForFile(localFile);

            using SftpFile remoteFile = (await OpenFileCoreAsync(remotePath, (overwrite ? SftpOpenFlags.OpenOrCreate : SftpOpenFlags.CreateNew) | SftpOpenFlags.Write, permissions.Value, cancellationToken))!;

            length ??= RandomAccess.GetLength(localFile);

            ValueTask previous = default;

            for (long offset = 0; offset < length; offset += GetMaxWritePayload(remoteFile.Handle))
            {
                // Obtain a buffer before starting the copy to ensure we're not competing
                // for buffers with the previous copy.
                await s_uploadBufferSemaphore.WaitAsync(cancellationToken);
                previous = CopyBuffer(previous, offset, GetMaxWritePayload(remoteFile.Handle));
            }

            await previous;

            await remoteFile.CloseAsync(cancellationToken);

            async ValueTask CopyBuffer(ValueTask previousCopy, long offset, int length)
            {
                byte[]? buffer = null;
                try
                {
                    buffer = ArrayPool<byte>.Shared.Rent(length);
                    do
                    {
                        int bytesRead = RandomAccess.Read(localFile, buffer.AsSpan(0, length), offset);
                        if (bytesRead == 0)
                        {
                            break;
                        }
                        await remoteFile.WriteAtAsync(buffer.AsMemory(0, bytesRead), offset, cancellationToken);
                        length -= bytesRead;
                        offset += bytesRead;
                    } while (length > 0);

                    await previousCopy;
                }
                finally
                {
                    if (buffer != null)
                    {
                        ArrayPool<byte>.Shared.Return(buffer);
                    }
                    s_uploadBufferSemaphore.Release();
                }
            }
        }

        public ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, CancellationToken cancellationToken = default)
            => DownloadDirectoryEntriesAsync(remoteDirPath, localDirPath, options: null, cancellationToken);

        public async ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, DownloadEntriesOptions? options, CancellationToken cancellationToken = default)
        {
            options ??= DefaultDownloadEntriesOptions;

            const UnixFileTypeFilter SupportedFileTypes =
                UnixFileTypeFilter.RegularFile |
                UnixFileTypeFilter.Directory |
                UnixFileTypeFilter.SymbolicLink;
            UnixFileTypeFilter unsupportedFileTypes = options.FileTypeFilter & ~SupportedFileTypes;
            if (unsupportedFileTypes != 0)
            {
                throw new NotSupportedException($"{nameof(options.FileTypeFilter)} includes unsupported file types: {unsupportedFileTypes}. {nameof(options.FileTypeFilter)} may only include {SupportedFileTypes}.");
            }

            bool overwrite = options.Overwrite;

            int trimRemoteDirectory = remoteDirPath.Length;
            if (!LocalPath.EndsInDirectorySeparator(remoteDirPath))
            {
                trimRemoteDirectory++;
            }
            localDirPath = LocalPath.EnsureTrailingSeparator(localDirPath);
            if (!Directory.Exists(localDirPath))
            {
                throw new DirectoryNotFoundException($"Directory not found: {localDirPath}.");
            }
            // Track the last directory that is known to exist to avoid calling Directory.CreateDirectory for each item in the same directory.
            string lastDirectory = localDirPath;

            char[] pathBuffer = ArrayPool<char>.Shared.Rent(4096);
            var fse = GetDirectoryEntriesAsync<(string LocalPath, string RemotePath, UnixFileType Type, UnixFilePermissions Permissions, long Length)>(remoteDirPath,
                (ref SftpFileEntry entry) =>
                {
                    string remotePath = entry.ToPath();
                    using ValueStringBuilder localPathBuilder = new(pathBuffer);
                    localPathBuilder.Append(localDirPath);
                    localPathBuilder.Append(remotePath.Substring(trimRemoteDirectory));
                    return (localPathBuilder.ToString(), remotePath, entry.FileType, entry.Permissions, entry.Length);
                },
                new EnumerationOptions() {
                        RecurseSubdirectories = options.RecurseSubdirectories,
                        FollowDirectoryLinks = options.FollowDirectoryLinks,
                        FollowFileLinks = options.FollowFileLinks,
                        FileTypeFilter = options.FileTypeFilter,
                        ShouldInclude = options.ShouldInclude,
                        ShouldRecurse = options.ShouldRecurse });

            var onGoing = new Queue<ValueTask>();
            try
            {
                await foreach (var item in fse.WithCancellation(cancellationToken))
                {
                    if (onGoing.Count == MaxConcurrentOperations)
                    {
                        await onGoing.Dequeue();
                    }
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
                                CreateLocalDirectory(item.LocalPath, item.Permissions);
                            }
                            lastDirectory = item.LocalPath;
                            break;
                        case UnixFileType.RegularFile:
                            lastDirectory = EnsureParentDirectory(lastDirectory, item.LocalPath);
                            onGoing.Enqueue(DownloadFileAsync(item.RemotePath, item.LocalPath, item.Length, overwrite, item.Permissions, cancellationToken));
                            break;
                        case UnixFileType.SymbolicLink:
                            lastDirectory = EnsureParentDirectory(lastDirectory, item.LocalPath);
                            onGoing.Enqueue(DownloadLinkAsync(item.RemotePath, item.LocalPath, overwrite, cancellationToken));
                            break;
                        default:
                            throw new NotSupportedException($"Downloading file type '{item.Type}' is not supported.");
                    }
                }
                while (onGoing.TryDequeue(out ValueTask pending))
                {
                    await pending;
                }
            }
            finally
            {
                while (onGoing.TryDequeue(out ValueTask pending))
                {
                    try
                    {
                        await pending;
                    }
                    catch
                    { }
                }
                ArrayPool<char>.Shared.Return(pathBuffer);
            }

            static string EnsureParentDirectory(string lastDirectory, string itemPath)
            {
                ReadOnlySpan<char> parentPath = Path.GetDirectoryName(itemPath.AsSpan());
                bool isSameOrParentOfCurrent =
                    lastDirectory.AsSpan().StartsWith(parentPath) &&
                    (lastDirectory.Length == parentPath.Length || LocalPath.IsDirectorySeparator(lastDirectory[parentPath.Length]));
                if (!isSameOrParentOfCurrent)
                {
                    lastDirectory = new string(parentPath);
                    Directory.CreateDirectory(lastDirectory);
                }
                return lastDirectory;
            }
        }

        private static void CreateLocalDirectory(string path, UnixFilePermissions permissions)
        {
#if NET7_0_OR_GREATER
            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(path);
            }
            else
            {
                Directory.CreateDirectory(path, (permissions & CreateDirectoryPermissionMask).ToUnixFileMode());
            }
#else
            Directory.CreateDirectory(path);
#endif
        }

        private static FileStream OpenFileStream(string path, FileMode mode, FileAccess access, FileShare share, UnixFilePermissions permissions)
        {
            var options = new FileStreamOptions()
            {
                Mode = mode,
                BufferSize = 0,
                Access = access,
                Share = share
            };
#if NET7_0_OR_GREATER
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = (permissions & CreateFilePermissionMask).ToUnixFileMode();
            }
#endif
            return new FileStream(path, options);
        }

        private async ValueTask DownloadLinkAsync(string remotePath, string localPath, bool overwrite, CancellationToken cancellationToken)
        {
            bool exists =
#if NET7_0_OR_GREATER
             Path.Exists(localPath);
#else
             File.Exists(localPath) || Directory.Exists(localPath);
#endif
            if (!overwrite && exists)
            {
                throw new IOException($"The file '{localPath}' already exists.");
            }

            // note: the remote server is expected to return a path that has forward slashes, also when that server runs on Windows.
            string targetPath = await GetLinkTargetAsync(remotePath, cancellationToken);
            if (exists)
            {
                File.Delete(localPath);
            }
            File.CreateSymbolicLink(localPath, targetPath);
        }

        public ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, CancellationToken cancellationToken = default)
            => DownloadFileAsync(remoteFilePath, localFilePath, overwrite: false, cancellationToken);

        public ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, bool overwrite, CancellationToken cancellationToken = default)
            => DownloadFileAsync(remoteFilePath, localFilePath, length: null, overwrite, permissions: null, cancellationToken);

        private async ValueTask DownloadFileAsync(string remotePath, string localPath, long? length, bool overwrite, UnixFilePermissions? permissions, CancellationToken cancellationToken)
        {
            ValueTask<FileEntryAttributes?> getAttributes = length == null || permissions == null ? GetAttributesAsync(remotePath, followLinks: true) : default;

            using SftpFile? remoteFile = await OpenFileAsync(remotePath, FileAccess.Read, cancellationToken);
            if (remoteFile is null)
            {
                return;
            }

            if (length == null || permissions == null)
            {
                FileEntryAttributes? attributes = await getAttributes;
                if (attributes is null)
                {
                    throw new SftpException(SftpError.NoSuchFile);
                }
                length = attributes.Length;
                permissions = attributes.Permissions;
            }

            using FileStream localFile = OpenFileStream(localPath, overwrite ? FileMode.Create : FileMode.CreateNew, FileAccess.Write, FileShare.None, permissions!.Value);

            ValueTask previous = default;

            for (long offset = 0; offset < length; offset += MaxReadPayload)
            {
                // Obtain a buffer before starting the copy to ensure we're not competing
                // for buffers with the previous copy.
                await s_downloadBufferSemaphore.WaitAsync(cancellationToken);
                previous = CopyBuffer(previous, offset, MaxReadPayload);
            }

            await previous;

            await remoteFile.CloseAsync(cancellationToken);

            async ValueTask CopyBuffer(ValueTask previousCopy, long offset, int length)
            {
                byte[]? buffer = null;
                try
                {
                    buffer = ArrayPool<byte>.Shared.Rent(length);
                    do
                    {
                        int bytesRead = await remoteFile.ReadAtAsync(buffer, offset, cancellationToken);
                        if (bytesRead == 0)
                        {
                            break;
                        }
                        RandomAccess.Write(localFile.SafeFileHandle, buffer.AsSpan(0, bytesRead), offset);
                        length -= bytesRead;
                        offset += bytesRead;
                    } while (length > 0);

                    await previousCopy;
                }
                finally
                {
                    if (buffer != null)
                    {
                        ArrayPool<byte>.Shared.Return(buffer);
                    }
                    s_downloadBufferSemaphore.Release();
                }
            }
        }

        private ValueTask CreateNewDirectoryAsync(ReadOnlySpan<char> path, bool awaitable, UnixFilePermissions permissions, CancellationToken cancellationToken)
        {
            PacketType packetType = PacketType.SSH_FXP_MKDIR;

            int id = GetNextId();
            PendingOperation? pendingOperation = awaitable ? CreatePendingOperation(packetType) : null;

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(path);
            packet.WriteAttributes(permissions: permissions & CreateDirectoryPermissionMask, fileType: UnixFileType.Directory);

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

        private async ValueTask<ReadOnlyMemory<byte>> ReadPacketAsync(CancellationToken cancellationToken)
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
                    ReadOnlyMemory<byte> packet = await ReadPacketAsync(cancellationToken: default);
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

        internal ValueTask<FileEntryAttributes> GetAttributesForHandleAsync(byte[] handle, CancellationToken cancellationToken = default)
        {
            PacketType packetType = PacketType.SSH_FXP_FSTAT;

            int id = GetNextId();
            PendingOperation pendingOperation = CreatePendingOperation(packetType);

            Packet packet = new Packet(packetType);
            packet.WriteInt(id);
            packet.WriteString(handle);

            return ExecuteAsync<FileEntryAttributes>(packet, id, pendingOperation, cancellationToken);
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