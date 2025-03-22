// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Buffers;
using System.IO.Enumeration;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Tmds.Ssh;

sealed partial class SftpChannel : IDisposable
{
    const UnixFilePermissions OwnershipPermissions = SftpClient.OwnershipPermissions;
    const UnixFilePermissions CreateFilePermissionMask = OwnershipPermissions;
    const UnixFilePermissions CreateDirectoryPermissionMask = OwnershipPermissions | UnixFilePermissions.StickyBit;
    const UnixFilePermissions PretendUMask = UnixFilePermissions.OtherWrite;

    // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
    // This is the version implemented by OpenSSH.
    const uint ProtocolVersion = 3;

    const int MaxConcurrentOperations = 64;
    // Limit the number of buffers allocated for copying.
    // An onGoing ValueTask may allocate multiple buffers.
    const int MaxConcurrentBuffers = 64;

    internal SftpChannel(ISshChannel channel, SftpClientOptions options, string? workingDirectory)
    {
        _channel = channel;
        _receivePacketSize = _channel.ReceiveMaxPacket;
        _options = options;
        WorkingDirectory = workingDirectory ?? "";
    }

    public CancellationToken ChannelAborted
        => _channel.ChannelAborted;

    private readonly ISshChannel _channel;
    private readonly SftpClientOptions _options;

    // Limits the number of buffers concurrently used for uploading/downloading.
    private readonly SemaphoreSlim s_downloadBufferSemaphore = new SemaphoreSlim(MaxConcurrentBuffers, MaxConcurrentBuffers);
    private readonly SemaphoreSlim s_uploadBufferSemaphore = new SemaphoreSlim(MaxConcurrentBuffers, MaxConcurrentBuffers);

    private byte[]? _packetBuffer;
    private int _nextId = 5;
    private int GetNextId() => Interlocked.Increment(ref _nextId);
    private int _receivePacketSize;
    private SftpExtension _supportedExtensions;
    public string WorkingDirectory { get; private set; }

    internal int GetMaxWritePayload(byte[] handle) // SSH_FXP_WRITE payload
        => _channel.SendMaxPacket
            - 4 /* packet length */ - 1 /* packet type */ - 4 /* id */
            - 4 /* handle length */ - handle.Length - 8 /* offset */ - 4 /* data length */;

    internal int MaxReadPayload // SSH_FXP_DATA payload
        => _channel.ReceiveMaxPacket
            - 4 /* packet length */ - 1 /* packet type */ - 4 /* id */ - 4 /* payload length */;

    internal int GetCopyBetweenSftpFilesBufferSize(byte[] destinationHandle)
        => Math.Min(MaxReadPayload, GetMaxWritePayload(destinationHandle));

    internal SftpExtension EnabledExtensions => _supportedExtensions;

    private bool SupportsCopyData => (_supportedExtensions & SftpExtension.CopyData) != 0;

    public void Dispose()
    {
        _channel.Dispose();
    }

    public ValueTask<SftpFile?> OpenFileAsync(string workingDirectory, string path, SftpOpenFlags flags, FileAccess access, FileOpenOptions options, CancellationToken cancellationToken)
    {
        flags = GetOpenFlags(flags, access, options.OpenMode);

        ValueTask<SftpFile?> result = OpenFileCoreAsync(workingDirectory, path, flags, options.CreatePermissions, options, cancellationToken);

        if (options.CacheLength)
        {
            result = SetCachedLengthAsync(result, cancellationToken);
        }

        return result;
    }

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

    private async ValueTask<SftpFile?> SetCachedLengthAsync(ValueTask<SftpFile?> fileOpenTask, CancellationToken cancellationToken)
    {
        SftpFile? file = await fileOpenTask.ConfigureAwait(false);
        if (file is not null)
        {
            try
            {
                long length = await file.GetLengthAsync(cancellationToken);
                file.SetCachedLength(length);
            }
            catch
            {
                file.Dispose();

                throw;
            }
        }
        return file;
    }

    private ValueTask<SftpFile?> OpenFileCoreAsync(string workingDirectory, string path, SftpOpenFlags flags, UnixFilePermissions permissions, FileOpenOptions options, CancellationToken cancellationToken)
    {
        PacketType packetType = PacketType.SSH_FXP_OPEN;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType, options);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WritePath(workingDirectory, path);
        packet.WriteUInt((uint)flags);
        packet.WriteAttributes(permissions: permissions & CreateFilePermissionMask, fileType: UnixFileType.RegularFile);

        return ExecuteAsync<SftpFile?>(packet, id, pendingOperation, cancellationToken);
    }

    public ValueTask DeleteFileAsync(string workingDirectory, string path, CancellationToken cancellationToken = default)
    {
        PacketType packetType = PacketType.SSH_FXP_REMOVE;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WritePath(workingDirectory, path);

        return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
    }

    public ValueTask DeleteDirectoryAsync(string workingDirectory, string path, bool recursive, CancellationToken cancellationToken = default)
    {
        if (recursive)
        {
            return DeleteDirectoryRecursiveAsync(workingDirectory, path, cancellationToken);
        }
        else
        {
            return DeleteDirectoryAsync(workingDirectory, path, cancellationToken);
        }
    }

    private ValueTask DeleteDirectoryAsync(string workingDirectory, string path, CancellationToken cancellationToken = default)
    {
        PacketType packetType = PacketType.SSH_FXP_RMDIR;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WritePath(workingDirectory, path);

        return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
    }

    private async ValueTask DeleteDirectoryRecursiveAsync(string workingDirectory, string path, CancellationToken cancellationToken = default)
    {
        path = RemotePath.ResolvePath([workingDirectory, path]);

        var onGoing = new Queue<ValueTask>();

        var fse = GetDirectoryEntriesAsync<string>(
            path,
            (ref SftpFileEntry entry) => entry.ToPath(),
            new EnumerationOptions()
            {
                RecurseSubdirectories = true,
                FollowDirectoryLinks = false,
                FollowFileLinks = false,
                FileTypeFilter = ~UnixFileTypeFilter.Directory,
                DirectoryCompleted = (string dir) => onGoing.Enqueue(DeleteDirectoryAsync("", dir, cancellationToken))
            });

        try
        {
            await foreach (var item in fse.WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                while (onGoing.TryPeek(out ValueTask first) && first.IsCompleted)
                {
                    await onGoing.Dequeue().ConfigureAwait(false);
                }

                onGoing.Enqueue(DeleteFileAsync("", item, cancellationToken));
            }

            while (onGoing.TryDequeue(out ValueTask pending))
            {
                await pending.ConfigureAwait(false);
            }
        }
        finally
        {
            while (onGoing.TryDequeue(out ValueTask pending))
            {
                try
                {
                    await pending.ConfigureAwait(false);
                }
                catch
                { }
            }
        }

        await DeleteDirectoryAsync("", path, cancellationToken);
    }

    public ValueTask RenameAsync(string workingDirectory, string oldPath, string newPath, CancellationToken cancellationToken = default)
    {
        PacketType packetType = PacketType.SSH_FXP_RENAME;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WritePath(workingDirectory, oldPath);
        packet.WritePath(workingDirectory, newPath);

        return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
    }

    public async ValueTask CopyFileAsync(string workingDirectory, string sourcePath, string destinationPath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        // Get the source file attributes and open it in parallel.
        // We get the attribute to dermine the permissions for the destination path.
        ValueTask<FileEntryAttributes?> sourceAttributesTask = GetAttributesAsync(workingDirectory, sourcePath, followLinks: true, filter: [], cancellationToken);
        using SftpFile? sourceFile = await OpenFileCoreAsync(workingDirectory, sourcePath, SftpOpenFlags.Open | SftpOpenFlags.Read, default(UnixFilePermissions), SftpClient.DefaultFileOpenOptions, cancellationToken).ConfigureAwait(false);
        if (sourceFile is null)
        {
            throw new SftpException(SftpError.NoSuchFile);
        }
        // Get the attributes ignoring any errors and falling back to getting them from the handle (unlikely).
        FileEntryAttributes? sourceAttributes = null;
        try
        {
            sourceAttributes = await sourceAttributesTask;
        }
        catch
        { }
        if (sourceAttributes is null)
        {
            sourceAttributes = await sourceFile.GetAttributesAsync(cancellationToken).ConfigureAwait(false);
        }

        UnixFilePermissions permissions = sourceAttributes.Permissions & OwnershipPermissions; // Do not preserve setid bits (since the owner may change).

        // Refresh our source length from the handle (in parallel with with opening the destination file).
#pragma warning disable CS8619 // Nullability of reference types in value doesn't match target type.
        sourceAttributesTask = sourceFile.GetAttributesAsync(cancellationToken);
#pragma warning restore CS8619

        // When we are overwriting, the file may exists and be larger than the source file.
        // We could open with Truncate but then the user would lose their data if they (by accident) uses a source and destination that are the same file.
        // To avoid that, we'll truncate after copying the data instead.
        SftpOpenFlags openFlags = overwrite ? SftpOpenFlags.OpenOrCreate : SftpOpenFlags.CreateNew;
        using SftpFile destinationFile = (await OpenFileCoreAsync(workingDirectory, destinationPath, openFlags | SftpOpenFlags.Write, permissions, SftpClient.DefaultFileOpenOptions, cancellationToken).ConfigureAwait(false))!;

        // Get the length before we start writing so we know if we need to truncate.
        ValueTask<long> initialLengthTask = overwrite ? destinationFile.GetLengthAsync(cancellationToken) : ValueTask.FromResult(0L);

        long copyLength = (await sourceAttributesTask.ConfigureAwait(false))!.Length;
        if (copyLength > 0)
        {
            bool doCopyAsync = true;
            if (SupportsCopyData)
            {
                try
                {
                    await CopyDataAsync(sourceFile.Handle, 0, destinationFile.Handle, 0, (ulong)copyLength, cancellationToken).ConfigureAwait(false);
                    doCopyAsync = false;
                }
                catch (SftpException ex) when (ex.Error == SftpError.Eof ||   // source has less data than copyLength (unlikely).
                                                ex.Error == SftpError.Failure) // (maybe) source and destination are same path
                {
                    // Fall through to async copy.
                }
            }

            if (doCopyAsync)
            {
                await CopyAsync(copyLength, cancellationToken).ConfigureAwait(false);
            }
        }

        // Truncate if the sourceFile is smaller than the destination file's initial length.
        long initialLength = await initialLengthTask.ConfigureAwait(false);
        if (initialLength > copyLength)
        {
            await destinationFile.SetLengthAsync(copyLength).ConfigureAwait(false);
        }

        async ValueTask CopyAsync(long length, CancellationToken cancellationToken)
        {
            Debug.Assert(length > 0);

            int bufferSize = GetCopyBetweenSftpFilesBufferSize(destinationFile.Handle);

            ValueTask previous = default;

            CancellationTokenSource breakLoop = new();

            for (long offset = 0; offset < length; offset += bufferSize)
            {
                if (!breakLoop.IsCancellationRequested)
                {
                    await s_downloadBufferSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                    previous = CopyBuffer(previous, offset, bufferSize);
                }
            }

            await previous.ConfigureAwait(false);

            async ValueTask CopyBuffer(ValueTask previousCopy, long offset, int length)
            {
                try
                {
                    do
                    {
                        byte[]? buffer = null;
                        try
                        {
                            int bytesRead;
                            try
                            {
                                if (breakLoop.IsCancellationRequested)
                                {
                                    return;
                                }

                                buffer = ArrayPool<byte>.Shared.Rent(length);
                                bytesRead = await sourceFile.ReadAtAsync(buffer.AsMemory(0, length), sourceFile.Position + offset, cancellationToken).ConfigureAwait(false);
                                if (bytesRead == 0)
                                {
                                    break;
                                }

                                // Our download buffer becomes an upload buffer.
                                await s_uploadBufferSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                            }
                            catch
                            {
                                breakLoop.Cancel();
                                throw;
                            }
                            finally
                            {
                                s_downloadBufferSemaphore.Release();
                            }
                            try
                            {
                                await destinationFile.WriteAtAsync(buffer.AsMemory(0, bytesRead), offset).ConfigureAwait(false);
                                length -= bytesRead;
                                offset += bytesRead;
                            }
                            catch
                            {
                                breakLoop.Cancel();
                                throw;
                            }
                            finally
                            {
                                if (buffer != null)
                                {
                                    ArrayPool<byte>.Shared.Return(buffer);
                                    buffer = null;
                                }
                                s_uploadBufferSemaphore.Release();
                            }
                        }
                        finally
                        {
                            if (buffer != null)
                            {
                                ArrayPool<byte>.Shared.Return(buffer);
                            }
                        }
                        if (length > 0)
                        {
                            await s_downloadBufferSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                        }
                    } while (length > 0);
                }
                finally
                {
                    await previousCopy.ConfigureAwait(false);
                }
            }
        }
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-extensions-00#section-7
    private ValueTask CopyDataAsync(byte[] sourceFileHandle, ulong sourceOffset, byte[] destinationFileHandle, ulong destinationOffset, ulong? length, CancellationToken cancellationToken = default)
    {
        Debug.Assert((_supportedExtensions & SftpExtension.CopyData) != 0);

        if (length == 0)
        {
            return default;
        }

        /*
            byte   SSH_FXP_EXTENDED
            uint32 request-id
            string "copy-data"
            string read-from-handle
            uint64 read-from-offset
            uint64 read-data-length
            string write-to-handle
            uint64 write-to-offset
        */
        PacketType packetType = PacketType.SSH_FXP_EXTENDED;
        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(PacketType.SSH_SFTP_STATUS_RESPONSE);
        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WriteString("copy-data");
        packet.WriteString(sourceFileHandle);
        packet.WriteUInt64(sourceOffset);
        packet.WriteUInt64(length ?? 0);
        packet.WriteString(destinationFileHandle);
        packet.WriteUInt64(destinationOffset);
        return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
    }

    public ValueTask<FileEntryAttributes?> GetAttributesAsync(string workingDirectory, string path, bool followLinks, string[]? filter, CancellationToken cancellationToken = default)
    {
        PacketType packetType = followLinks ? PacketType.SSH_FXP_STAT : PacketType.SSH_FXP_LSTAT;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType, filter);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WritePath(workingDirectory, path);

        return ExecuteAsync<FileEntryAttributes?>(packet, id, pendingOperation, cancellationToken);
    }

    public ValueTask SetAttributesAsync(
        string workingDirectory,
        string path,
        UnixFilePermissions? permissions = default,
        (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
        long? length = default,
        (int Uid, int Gid)? ids = default,
        IEnumerable<KeyValuePair<string, Memory<byte>>>? extendedAttributes = default,
        CancellationToken cancellationToken = default)
    {
        EnsureAttributesHasValue(
            length: length,
            ids: ids,
            permissions: permissions,
            times: times,
            extendedAttributes: extendedAttributes);


        PacketType packetType = PacketType.SSH_FXP_SETSTAT;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WritePath(workingDirectory, path);
        packet.WriteAttributes(length: length,
                               ids: ids,
                               permissions: permissions,
                               times: times,
                               extendedAttributes: extendedAttributes);

        return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
    }

    internal ValueTask SetAttributesForHandleAsync(
        byte[] handle,
        long? length = default,
        (int Uid, int Gid)? ids = default,
        UnixFilePermissions? permissions = default,
        (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
        IEnumerable<KeyValuePair<string, Memory<byte>>>? extendedAttributes = default,
        CancellationToken cancellationToken = default)
    {
        EnsureAttributesHasValue(
            length: length,
            ids: ids,
            permissions: permissions,
            times: times,
            extendedAttributes: extendedAttributes);

        PacketType packetType = PacketType.SSH_FXP_FSETSTAT;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WriteString(handle);
        packet.WriteAttributes(length: length,
                               ids: ids,
                               permissions: permissions,
                               times: times,
                               extendedAttributes: extendedAttributes);

        return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
    }

    private void EnsureAttributesHasValue(
        long? length,
        (int Uid, int Gid)? ids,
        UnixFilePermissions? permissions,
        (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times,
        IEnumerable<KeyValuePair<string, Memory<byte>>>? extendedAttributes)
    {
        if (!length.HasValue &&
            !ids.HasValue &&
            !permissions.HasValue &&
            !times.HasValue &&
            (extendedAttributes is null || !extendedAttributes.Any()))
        {
            throw new ArgumentException("No value specified.");
        }
    }

    public ValueTask<string> GetLinkTargetAsync(string workingDirectory, string linkPath, CancellationToken cancellationToken = default)
    {
        PacketType packetType = PacketType.SSH_FXP_READLINK;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WritePath(workingDirectory, linkPath);

        return ExecuteAsync<string>(packet, id, pendingOperation, cancellationToken);
    }

    public ValueTask<string> GetRealPathAsync(string workingDirectory, string path, CancellationToken cancellationToken = default)
    {
        PacketType packetType = PacketType.SSH_FXP_REALPATH;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WriteString(path);

        return ExecuteAsync<string>(packet, id, pendingOperation, cancellationToken);
    }

    public ValueTask CreateSymbolicLinkAsync(string workingDirectory, string linkPath, string targetPath, bool overwrite, CancellationToken cancellationToken)
    {
        int id;
        Packet packet;

        if (overwrite)
        {
            id = GetNextId();

            packet = new Packet(PacketType.SSH_FXP_REMOVE);
            packet.WriteInt(id);
            packet.WritePath(workingDirectory, linkPath);

            _ = ExecuteAsync(packet, id, pendingOperation: null, cancellationToken: default);
        }

        PacketType packetType = PacketType.SSH_FXP_SYMLINK;

        id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType);

        packet = new Packet(packetType);
        packet.WriteInt(id);
        // ... OpenSSH has these arguments swapped: https://bugzilla.mindrot.org/show_bug.cgi?id=861
        packet.WriteString(targetPath);
        packet.WritePath(workingDirectory, linkPath);

        return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
    }

    public ValueTask<SftpFile?> OpenDirectoryAsync(string workingDirectory, string path, CancellationToken cancellationToken = default)
    {
        PacketType packetType = PacketType.SSH_FXP_OPENDIR;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WritePath(workingDirectory, path);

        // note: Return as 'SftpFile' so it gets Disposed in case the open is cancelled.
        return ExecuteAsync<SftpFile?>(packet, id, pendingOperation, cancellationToken);
    }

    public async ValueTask CreateDirectoryAsync(string workingDirectory, string path, bool createParents = false, UnixFilePermissions permissions = SftpClient.DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default)
    {
        // This method doesn't throw if the target directory already exists.
        // We run a SSH_FXP_STAT in parallel with the SSH_FXP_MKDIR to check if the target directory already exists.
        ValueTask<FileEntryAttributes?> checkExists = GetAttributesAsync(workingDirectory, path, followLinks: true /* allow the path to be a link to a dir */, filter: [], cancellationToken);
        ValueTask mkdir = CreateNewDirectoryAsync(workingDirectory, path, createParents, SftpClient.DefaultCreateDirectoryPermissions, cancellationToken);

        try
        {
            await mkdir.ConfigureAwait(false);
            await IsDirectory(checkExists).ConfigureAwait(false);
        }
        catch (SftpException ex) when (ex.Error == SftpError.Failure)
        {
            if (await IsDirectory(checkExists).ConfigureAwait(false))
            {
                return;
            }

            throw;
        }

        async ValueTask<bool> IsDirectory(ValueTask<FileEntryAttributes?> checkExists)
        {
            try
            {
                FileEntryAttributes? attributes = await checkExists.ConfigureAwait(false);
                return attributes?.FileType == UnixFileType.Directory;
            }
            catch
            {
                return false;
            }
        }
    }

    public async ValueTask CreateNewDirectoryAsync(string workingDirectory, string path, bool createParents = false, UnixFilePermissions permissions = SftpClient.DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default)
    {
        if (createParents)
        {
            CreateParents(path);
        }

        await CreateNewDirectory(workingDirectory, path.AsSpan(), awaitable: true, permissions, cancellationToken).ConfigureAwait(false);

        void CreateParents(string path)
        {
            ReadOnlySpan<char> span = RemotePath.TrimEndingDirectorySeparators(path);
            int offset = 1;
            int idx;
            while ((idx = span.Slice(offset).IndexOf(RemotePath.DirectorySeparatorChar)) != -1)
            {
                offset += idx;
                // note: parent directories are created using the default permissions, not the permissions arg.
                _ = CreateNewDirectory(workingDirectory, span.Slice(0, offset), awaitable: false, permissions: SftpClient.DefaultCreateDirectoryPermissions, cancellationToken: default);
                offset++;
            }
        }
    }

    public async ValueTask UploadDirectoryEntriesAsync(string workingDirectory, string localDirPath, string remoteDirPath, UploadEntriesOptions? options, CancellationToken cancellationToken = default)
    {
        options ??= SftpClient.DefaultUploadEntriesOptions;
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

        LocalFileEntryPredicate? shouldRecurse = options.ShouldRecurse;
        if (recurse && (!followDirectoryLinks || shouldRecurse is not null))
        {
            fse.ShouldRecursePredicate = (ref FileSystemEntry entry) =>
            {
                bool isLink = (entry.Attributes & FileAttributes.ReparsePoint) != 0;
                if (isLink && !followDirectoryLinks)
                {
                    return false;
                }

                if (shouldRecurse is null)
                {
                    return true;
                }

                LocalFileEntry localFileEntry = new LocalFileEntry(ref entry);
                return shouldRecurse(ref localFileEntry);
            };
        }

        var onGoing = new Queue<ValueTask>();
        var bufferSemaphore = new SemaphoreSlim(MaxConcurrentBuffers, MaxConcurrentBuffers);
        try
        {
            foreach (var item in fse)
            {
                if (onGoing.Count == MaxConcurrentOperations)
                {
                    await onGoing.Dequeue().ConfigureAwait(false);
                }
                switch (item.Type)
                {
                    case UnixFileType.Directory:
                        if (overwrite)
                        {
                            onGoing.Enqueue(CreateDirectoryAsync(workingDirectory, item.RemotePath, createParents: false, GetPermissionsForDirectory(item.LocalPath), cancellationToken));
                        }
                        else
                        {
                            onGoing.Enqueue(CreateNewDirectoryAsync(workingDirectory, item.RemotePath, createParents: false, GetPermissionsForDirectory(item.LocalPath), cancellationToken));
                        }
                        break;
                    case UnixFileType.RegularFile:
                        onGoing.Enqueue(UploadFileAsync(workingDirectory, item.LocalPath, item.RemotePath, item.Length, overwrite, permissions: null, cancellationToken));
                        break;
                    case UnixFileType.SymbolicLink:
                        FileInfo file = new FileInfo(item.LocalPath);
                        FileSystemInfo? linkTarget;
                        if (followFileLinks &&
                            (linkTarget = file.ResolveLinkTarget(returnFinalTarget: true))?.Exists == true)
                        {
                            // Pass linkTarget.Length because item.Length is the length of the link target path.
                            onGoing.Enqueue(UploadFileAsync(workingDirectory, item.LocalPath, item.RemotePath, ((FileInfo)linkTarget).Length, overwrite, permissions: null, cancellationToken));
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
                            onGoing.Enqueue(CreateSymbolicLinkAsync(workingDirectory, item.RemotePath, targetPath, overwrite, cancellationToken));
                        }
                        break;
                    default:
                        break;
                }
            }
            while (onGoing.TryDequeue(out ValueTask pending))
            {
                await pending.ConfigureAwait(false);
            }
        }
        finally
        {
            while (onGoing.TryDequeue(out ValueTask pending))
            {
                try
                {
                    await pending.ConfigureAwait(false);
                }
                catch
                { }
            }
            ArrayPool<char>.Shared.Return(pathBuffer);
        }
    }

    private static UnixFilePermissions GetPermissionsForDirectory(string directoryPath)
    {
        const UnixFilePermissions Default = SftpClient.DefaultCreateDirectoryPermissions & ~PretendUMask;
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
        const UnixFilePermissions Default = SftpClient.DefaultCreateFilePermissions & ~PretendUMask;
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

    public async ValueTask UploadFileAsync(string workingDirectory, string localPath, string remotePath, long? length, bool overwrite, UnixFilePermissions? permissions, CancellationToken cancellationToken)
    {
        using FileStream localFile = new FileStream(localPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 0);

        permissions ??= GetPermissionsForFile(localFile.SafeFileHandle);

        await UploadFileAsync(workingDirectory, localFile, remotePath, length, overwrite, permissions.Value, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask UploadFileAsync(string workingDirectory, Stream source, string remotePath, long? length, bool overwrite, UnixFilePermissions permissions, CancellationToken cancellationToken)
    {
        using SftpFile remoteFile = (await OpenFileCoreAsync(workingDirectory, remotePath, (overwrite ? SftpOpenFlags.OpenOrCreate : SftpOpenFlags.CreateNew) | SftpOpenFlags.Write, permissions, SftpClient.DefaultFileOpenOptions, cancellationToken).ConfigureAwait(false))!;

        // Pipeline the writes when the source is a sync, seekable Stream.
        bool pipelineSyncWrites = source.CanSeek && IsSyncStream(source);

        if (!pipelineSyncWrites)
        {
            await source.CopyToAsync(remoteFile, GetMaxWritePayload(remoteFile.Handle)).ConfigureAwait(false);

            await remoteFile.CloseAsync(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            length ??= source.Length;
            if (length == 0)
            {
                return;
            }

            ValueTask previous = default;
            long startOffset = source.Position;
            long bytesSuccesfullyWritten = 0;
            CancellationTokenSource breakLoop = new();
            int maxWritePayload = GetMaxWritePayload(remoteFile.Handle);

            for (long offset = 0; offset < length; offset += maxWritePayload)
            {
                if (!breakLoop.IsCancellationRequested)
                {
                    await s_uploadBufferSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                    int copyLength = (int)Math.Min((long)maxWritePayload, length.Value - offset);
                    previous = CopyBuffer(previous, offset, copyLength);
                }
            }

            bool ignorePositionUpdateException = false;
            try
            {
                await previous.ConfigureAwait(false);

                await remoteFile.CloseAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                ignorePositionUpdateException = true;

                throw;
            }
            finally
            {
                // Set the position to what was succesfully written.
                try
                {
                    source.Position = startOffset + bytesSuccesfullyWritten;
                }
                catch when (ignorePositionUpdateException)
                { }
            }

            async ValueTask CopyBuffer(ValueTask previousCopy, long offset, int length)
            {
                try
                {
                    byte[]? buffer = null;
                    try
                    {
                        if (breakLoop.IsCancellationRequested)
                        {
                            return;
                        }

                        buffer = ArrayPool<byte>.Shared.Rent(length);
                        int remaining = length;
                        long readOffset = startOffset + offset;
                        do
                        {
                            int bytesRead;
                            lock (breakLoop) // Ensure only one thread is reading the Stream concurrently.
                            {
                                source.Position = readOffset;
                                bytesRead = source.Read(buffer.AsSpan(length - remaining, remaining));
                            }
                            if (bytesRead == 0)
                            {
                                throw new IOException("Unexpected end of file. The source was truncated during the upload.");
                            }
                            remaining -= bytesRead;
                            readOffset += bytesRead;
                        } while (remaining > 0);

                        await remoteFile.WriteAtAsync(buffer.AsMemory(0, length), offset, cancellationToken).ConfigureAwait(false);
                    }
                    catch
                    {
                        length = 0; // Assume nothing was written succesfully.
                        breakLoop.Cancel();
                        throw;
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
                finally
                {
                    await previousCopy.ConfigureAwait(false);

                    // Update with our length after the previous write completed succesfully.
                    bytesSuccesfullyWritten += length;
                }
            }
        }
    }

    // Consider it okay to do sync operation on these types of streams.
    private static bool IsSyncStream(Stream stream)
        => stream is MemoryStream or FileStream;

    private IAsyncEnumerable<T> GetDirectoryEntriesAsync<T>(string path, SftpFileEntryTransform<T> transform, EnumerationOptions options)
        => new SftpFileSystemEnumerable<T>(this, path, transform, options);

    public async ValueTask DownloadDirectoryEntriesAsync(string workingDirectory, string remoteDirPath, string localDirPath, DownloadEntriesOptions? options, CancellationToken cancellationToken = default)
    {
        options ??= SftpClient.DefaultDownloadEntriesOptions;

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
        DownloadEntriesOptions.ReplaceCharacters replaceInvalidCharacters = options.ReplaceInvalidCharacters ?? throw new ArgumentNullException(nameof(options.ReplaceInvalidCharacters));

        remoteDirPath = RemotePath.ResolvePath([workingDirectory, remoteDirPath]);
        workingDirectory = "";

        int trimRemoteDirectory = remoteDirPath.Length;
        if (remoteDirPath.Length != 0 && !RemotePath.EndsInDirectorySeparator(remoteDirPath))
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
        var fse = GetDirectoryEntriesAsync<(string LocalPath, string RemotePath, UnixFileType Type, UnixFilePermissions Permissions, long Length)>(
            remoteDirPath,
            (ref SftpFileEntry entry) =>
            {
                string remotePath = entry.ToPath();
                string localPath;
                ReadOnlySpan<char> relativePath = remotePath.AsSpan(trimRemoteDirectory);
                if (!LocalPath.IsRemotePathValidLocalSubPath(relativePath))
                {
                    relativePath = replaceInvalidCharacters(relativePath, LocalPath.InvalidLocalPathChars, pathBuffer);
                    using ValueStringBuilder localPathBuilder = new(pathBuffer);
                    // relativePath may used pathBuffer for storage
                    // append it first so we don't overwrite it with localDirPath.
                    localPathBuilder.Append(relativePath);
                    localPathBuilder.Insert(0, localDirPath);
                    localPath = localPathBuilder.ToString();
                }
                else
                {
                    using ValueStringBuilder localPathBuilder = new(pathBuffer);
                    localPathBuilder.Append(localDirPath);
                    localPathBuilder.Append(relativePath);
                    localPath = localPathBuilder.ToString();
                }

                return (localPath, remotePath, entry.FileType, entry.Permissions, entry.Length);
            },
            new EnumerationOptions()
            {
                RecurseSubdirectories = options.RecurseSubdirectories,
                FollowDirectoryLinks = options.FollowDirectoryLinks,
                FollowFileLinks = options.FollowFileLinks,
                FileTypeFilter = options.FileTypeFilter,
                ShouldInclude = options.ShouldInclude,
                ShouldRecurse = options.ShouldRecurse
            });

        var onGoing = new Queue<ValueTask>();
        try
        {
            await foreach (var item in fse.WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                if (onGoing.Count == MaxConcurrentOperations)
                {
                    await onGoing.Dequeue().ConfigureAwait(false);
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
                        onGoing.Enqueue(DownloadFileAsync(workingDirectory, item.RemotePath, item.LocalPath, destination: null, item.Length, overwrite, item.Permissions, throwIfNotFound: false, cancellationToken));
                        break;
                    case UnixFileType.SymbolicLink:
                        lastDirectory = EnsureParentDirectory(lastDirectory, item.LocalPath);
                        onGoing.Enqueue(DownloadLinkAsync(workingDirectory, item.RemotePath, item.LocalPath, overwrite, cancellationToken));
                        break;
                    default:
                        throw new NotSupportedException($"Downloading file type '{item.Type}' is not supported.");
                }
            }
            while (onGoing.TryDequeue(out ValueTask pending))
            {
                await pending.ConfigureAwait(false);
            }
        }
        finally
        {
            while (onGoing.TryDequeue(out ValueTask pending))
            {
                try
                {
                    await pending.ConfigureAwait(false);
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

    private async ValueTask DownloadLinkAsync(string workingDirectory, string remotePath, string localPath, bool overwrite, CancellationToken cancellationToken)
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
        string targetPath = await GetLinkTargetAsync(workingDirectory, remotePath, cancellationToken).ConfigureAwait(false);
        if (exists)
        {
            File.Delete(localPath);
        }
        File.CreateSymbolicLink(localPath, targetPath);
    }

    public ValueTask DownloadFileAsync(string workingDirectory, string remoteFilePath, string localFilePath, bool overwrite = false, CancellationToken cancellationToken = default)
        => DownloadFileAsync(workingDirectory, remoteFilePath, localFilePath, destination: null, length: null, overwrite, permissions: null, throwIfNotFound: true, cancellationToken);

    public ValueTask DownloadFileAsync(string workingDirectory, string remotePath, Stream destination, CancellationToken cancellationToken = default)
        => DownloadFileAsync(workingDirectory, remotePath, localPath: null, destination, length: null, overwrite: false, permissions: null, throwIfNotFound: true, cancellationToken);

    private async ValueTask DownloadFileAsync(string workingDirectory, string remotePath, string? localPath, Stream? destination, long? length, bool overwrite, UnixFilePermissions? permissions, bool throwIfNotFound, CancellationToken cancellationToken)
    {
        // Call GetAttributesAsync in parallel with OpenFileAsync.
        // We don't need to pass the CancellationToken since GetAttributesAsync will complete before the awaited OpenFileAsync completes.
        ValueTask<FileEntryAttributes?> getAttributes = length == null || permissions == null ? GetAttributesAsync(workingDirectory, remotePath, followLinks: true, filter: []) : default;

        using SftpFile? remoteFile = await OpenFileAsync(workingDirectory, remotePath, SftpOpenFlags.Open, FileAccess.Read, SftpClient.DefaultFileOpenOptions, cancellationToken).ConfigureAwait(false);
        if (remoteFile is null)
        {
            if (throwIfNotFound)
            {
                throw new SftpException(SftpError.NoSuchFile);
            }
            return;
        }

        if (length == null || permissions == null)
        {
            FileEntryAttributes? attributes = await getAttributes.ConfigureAwait(false);
            if (attributes is null) // unlikely
            {
                attributes = await remoteFile.GetAttributesAsync(cancellationToken).ConfigureAwait(false);
            }
            length = attributes.Length;
            permissions = attributes.Permissions;
        }

        using FileStream? localFile = localPath is null ? null : OpenFileStream(localPath, overwrite ? FileMode.Create : FileMode.CreateNew, FileAccess.Write, FileShare.None, permissions.Value);
        destination ??= localFile;

        Debug.Assert(destination is not null);

        bool writeSync = IsSyncStream(destination);

        ValueTask previous = default;
        CancellationTokenSource? breakLoop = length > 0 ? new() : null;

        int maxPayload = MaxReadPayload;
        for (long offset = 0; offset < length; offset += maxPayload)
        {
            Debug.Assert(breakLoop is not null);
            if (!breakLoop.IsCancellationRequested)
            {
                await s_downloadBufferSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                long remaining = length.Value - offset;
                previous = CopyBuffer(previous, offset, remaining > maxPayload ? maxPayload : (int)remaining);
            }
        }

        await previous.ConfigureAwait(false);

        await remoteFile.CloseAsync(cancellationToken).ConfigureAwait(false);

        async ValueTask CopyBuffer(ValueTask previousCopy, long fileOffset, int length)
        {
            byte[]? buffer = null;
            try
            {
                try
                {
                    if (breakLoop.IsCancellationRequested)
                    {
                        // previousCopy will throw.
                        return;
                    }

                    buffer = ArrayPool<byte>.Shared.Rent(length);
                    int remaining = length;
                    long position = fileOffset;
                    do
                    {
                        int bytesRead = await remoteFile.ReadAtAsync(buffer.AsMemory(length - remaining, remaining), position, cancellationToken).ConfigureAwait(false);
                        if (bytesRead == 0)
                        {
                            // Unexpected EOF.
                            throw new SftpException(SftpError.Eof);
                        }
                        position += bytesRead;
                        remaining -= bytesRead;
                    } while (remaining > 0);
                }
                // Wait for the previous buffer to be written so we're writing sequentially to the file.
                finally
                {
                    await previousCopy.ConfigureAwait(false);
                }

                if (writeSync)
                {
                    destination.Write(buffer.AsSpan(0, length));
                }
                else
                {
                    await destination.WriteAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                breakLoop.Cancel();
                throw;
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

    private ValueTask CreateNewDirectory(string workingDirectory, ReadOnlySpan<char> path, bool awaitable, UnixFilePermissions permissions, CancellationToken cancellationToken)
    {
        PacketType packetType = PacketType.SSH_FXP_MKDIR;

        int id = GetNextId();
        PendingOperation? pendingOperation = awaitable ? CreatePendingOperation(packetType) : null;

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WritePath(workingDirectory, path);
        packet.WriteAttributes(permissions: permissions & CreateDirectoryPermissionMask, fileType: UnixFileType.Directory);

        return ExecuteAsync(packet, id, pendingOperation, cancellationToken);
    }

    internal async Task ProtocolInitAsync(CancellationToken cancellationToken)
    {
        {
            using Packet packet = new Packet(PacketType.SSH_FXP_INIT);
            packet.WriteUInt(ProtocolVersion);
            await _channel.WriteAsync(packet.Data, cancellationToken).ConfigureAwait(false);
        }
        // In parallel with the init, get the remote working dir.
        bool getWorkingDirectory = string.IsNullOrEmpty(WorkingDirectory);
        if (getWorkingDirectory)
        {
            using Packet packet = new Packet(PacketType.SSH_FXP_REALPATH);
            packet.WriteInt(GetNextId());
            packet.WriteString(".");
            await _channel.WriteAsync(packet.Data, cancellationToken).ConfigureAwait(false);
        }
        {
            ReadOnlyMemory<byte> versionPacket = await ReadPacketAsync(cancellationToken).ConfigureAwait(false);
            if (versionPacket.Length == 0)
            {
                throw new SshChannelException("Channel closed during SFTP protocol initialization.");
            }
            HandleVersionPacket(versionPacket.Span);
        }
        if (getWorkingDirectory)
        {
            ReadOnlyMemory<byte> pathPacket = await ReadPacketAsync(cancellationToken).ConfigureAwait(false);
            if (pathPacket.Length == 0)
            {
                throw new SshChannelException("Channel closed during SFTP protocol initialization.");
            }
            HandleWorkingDirectoryPacket(pathPacket.Span);
        }

        _ = ReadAllPacketsAsync();
        _ = SendPacketsAsync();
    }

    internal ValueTask<byte[]> ReadDirAsync(SftpFile file, CancellationToken cancellationToken)
    {
        PacketType packetType = PacketType.SSH_FXP_READDIR;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType);

        Packet packet = new Packet(packetType);
        packet.WriteInt(id);
        packet.WriteString(file.Handle);

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
            _packetBuffer = new byte[_receivePacketSize]; // TODO: rent from shared pool.
        }
        int totalReceived = 0;

        // Read packet length.
        do
        {
            Memory<byte> readBuffer = new Memory<byte>(_packetBuffer, totalReceived, 4 - totalReceived);
            (ChannelReadType type, int bytesRead) = await _channel.ReadAsync(readBuffer, default, cancellationToken).ConfigureAwait(false);
            if (type == ChannelReadType.Closed)
            {
                return default;
            }
            if (type != ChannelReadType.StandardOutput)
            {
                continue;
            }
            totalReceived += bytesRead;
        } while (totalReceived < 4);

        int packetLength = BinaryPrimitives.ReadInt32BigEndian(_packetBuffer);
        int totalReceiveLength = packetLength + 4;

        if (totalReceiveLength > _packetBuffer.Length)
        {
            // OpenSSH sends packets that are larger than ReceiveMaxPacket.
            // Increase the size to two times the ReceiveMaxPacket size.
            if (totalReceiveLength > 2 * _channel.ReceiveMaxPacket)
            {
                throw new InvalidDataException($"SFTP packet is {totalReceiveLength} bytes on channel with {_channel.ReceiveMaxPacket} packet size.");
            }
            _receivePacketSize = 2 * _channel.ReceiveMaxPacket;
            _packetBuffer = new byte[_receivePacketSize];
        }

        // Read packet.
        while (totalReceived < totalReceiveLength)
        {
            Memory<byte> readBuffer = new Memory<byte>(_packetBuffer, totalReceived, totalReceiveLength - totalReceived);
            (ChannelReadType type, int bytesRead) = await _channel.ReadAsync(readBuffer, default, cancellationToken).ConfigureAwait(false);
            if (type != ChannelReadType.StandardOutput)
            {
                throw new InvalidDataException($"Unexpected data type: {type}");
            }
            totalReceived += bytesRead;
        }
        return new ReadOnlyMemory<byte>(_packetBuffer, 4, packetLength);
    }

    private async Task SendPacketsAsync()
    {
        bool sendPackets = true;
        await foreach (Packet packet in _pendingSends.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            if (sendPackets)
            {
                try
                {
                    await _channel.WriteAsync(packet.Data).ConfigureAwait(false);
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
                ReadOnlyMemory<byte> packet = await ReadPacketAsync(cancellationToken: default).ConfigureAwait(false);
                if (packet.Length == 0)
                {
                    throw new SshChannelException("Channel closed by peer.");
                }
                int id = BinaryPrimitives.ReadInt32BigEndian(packet.Span.Slice(1));
                if (_pendingOperations.Remove(id, out PendingOperation? operation))
                {
                    operation.HandleReply(this, packet.Span);
                }
            } while (true);
        }
        catch (Exception ex)
        {
            _channel.Abort(ex);
        }
        finally
        {
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

    private void HandleVersionPacket(ReadOnlySpan<byte> packet)
    {
        PacketReader reader = new(packet);

        PacketType type = reader.ReadPacketType();

        if (type != PacketType.SSH_FXP_VERSION)
        {
            throw new SshChannelException($"Expected packet SSH_FXP_VERSION, but received {type}.");
        }

        uint version = reader.ReadUInt();
        if (version != ProtocolVersion)
        {
            throw new SshOperationException($"Unsupported protocol version {version}.");
        }

        SftpExtension supportedExtensions = default;
        while (!reader.Remainder.IsEmpty)
        {
            ReadOnlySpan<byte> extensionName = reader.ReadStringAsSpan();
            ReadOnlySpan<byte> extensionData = reader.ReadStringAsSpan();

            if (extensionName.SequenceEqual("copy-data"u8) && extensionData.SequenceEqual("1"u8))
            {
                supportedExtensions |= SftpExtension.CopyData;
            }
        }

        _supportedExtensions = supportedExtensions & ~_options.DisabledExtensions;
    }

    private void HandleWorkingDirectoryPacket(ReadOnlySpan<byte> packet)
    {
        PacketReader reader = new(packet);
        PacketType type = reader.ReadPacketType();
        if (type != PacketType.SSH_FXP_NAME)
        {
            throw new SshChannelException($"Expected packet SSH_FXP_NAME, but received {type}.");
        }
        reader.ReadInt(); // id
        reader.ReadInt(); // count
        WorkingDirectory = reader.ReadString(); // filename
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
    internal ValueTask<FileEntryAttributes> GetAttributesForHandleAsync(byte[] handle, string[]? filter, CancellationToken cancellationToken = default)
    {
        PacketType packetType = PacketType.SSH_FXP_FSTAT;

        int id = GetNextId();
        PendingOperation pendingOperation = CreatePendingOperation(packetType, filter);

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

            await WriteFileSingleAsync(handle, offset, buffer.Slice(0, writeLength), cancellationToken).ConfigureAwait(false);

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
