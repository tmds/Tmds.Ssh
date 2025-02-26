// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class SftpDirectory
{
    private const UnixFilePermissions OwnershipPermissions = SftpClient.OwnershipPermissions;
    private const UnixFilePermissions DefaultCreateDirectoryPermissions = SftpClient.DefaultCreateDirectoryPermissions;
    private const UnixFilePermissions DefaultCreateFilePermissions = SftpClient.DefaultCreateFilePermissions;
    private static EnumerationOptions DefaultEnumerationOptions => SftpClient.DefaultEnumerationOptions;
    private static UploadEntriesOptions DefaultUploadEntriesOptions => SftpClient.DefaultUploadEntriesOptions;
    private static DownloadEntriesOptions DefaultDownloadEntriesOptions => SftpClient.DefaultDownloadEntriesOptions;
    private static FileOpenOptions DefaultFileOpenOptions => SftpClient.DefaultFileOpenOptions;

    public string Path => _workingDirectory;

    private readonly SftpClient _sftpClient;
    private readonly string _workingDirectory;

    private ValueTask<SftpChannel> GetChannelAsync(CancellationToken cancellationToken)
        => _sftpClient.GetChannelAsync(cancellationToken);

    internal SftpDirectory(SftpClient sftpClient, string workingDirectory)
    {
        _sftpClient = sftpClient;
        _workingDirectory = workingDirectory;
    }

    public SftpDirectory GetDirectory(string path)
    {
        string dirPath = RemotePath.ResolvePath([_workingDirectory, path]);
        if (dirPath == _workingDirectory)
        {
            return this;
        }
        return new SftpDirectory(_sftpClient, dirPath);
    }

    public ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
        => OpenOrCreateFileAsync(path, access, options: null, cancellationToken);

    public async ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
        => await OpenFileAsync(path, SftpOpenFlags.OpenOrCreate, access, options, cancellationToken).ConfigureAwait(false)
            ?? throw new SftpException(SftpError.NoSuchFile);

    public ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
        => CreateNewFileAsync(path, access, options: null, cancellationToken);

    public async ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
        => await OpenFileAsync(path, SftpOpenFlags.CreateNew, access, options, cancellationToken).ConfigureAwait(false)
            ?? throw new SftpException(SftpError.NoSuchFile);

    public ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
        => OpenFileAsync(path, access, options: null, cancellationToken);

    public async ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
        => await OpenFileAsync(path, SftpOpenFlags.Open, access, options, cancellationToken).ConfigureAwait(false);

    private async ValueTask<SftpFile?> OpenFileAsync(string path, SftpOpenFlags flags, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        return await channel.OpenFileAsync(_workingDirectory, path, flags, access, options ?? DefaultFileOpenOptions, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DeleteFileAsync(string path, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.DeleteFileAsync(_workingDirectory, path, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DeleteDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.DeleteDirectoryAsync(_workingDirectory, path, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.RenameAsync(_workingDirectory, oldPath, newPath, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask CopyFileAsync(string sourcePath, string destinationPath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.CopyFileAsync(_workingDirectory, sourcePath, destinationPath, overwrite, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, bool followLinks = true, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        return await channel.GetAttributesAsync(_workingDirectory, path, followLinks, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask SetAttributesAsync(
        string path,
        UnixFilePermissions? permissions = default,
        (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
        long? length = default,
        (int Uid, int Gid)? ids = default,
        IEnumerable<KeyValuePair<string, Memory<byte>>>? extendedAttributes = default,
        CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.SetAttributesAsync(_workingDirectory, path, permissions, times, length, ids, extendedAttributes, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<string> GetLinkTargetAsync(string linkPath, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        return await channel.GetLinkTargetAsync(_workingDirectory, linkPath, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<string> GetRealPathAsync(string path, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        return await channel.GetRealPathAsync(_workingDirectory, path, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.CreateSymbolicLinkAsync(_workingDirectory, linkPath, targetPath, overwrite: false, cancellationToken).ConfigureAwait(false);
    }

    public IAsyncEnumerable<(string Path, FileEntryAttributes Attributes)> GetDirectoryEntriesAsync(string path, EnumerationOptions? options = null)
        => GetDirectoryEntriesAsync<(string, FileEntryAttributes)>(path, (ref SftpFileEntry entry) => (entry.ToPath(), entry.ToAttributes()), options);

    public IAsyncEnumerable<T> GetDirectoryEntriesAsync<T>(string path, SftpFileEntryTransform<T> transform, EnumerationOptions? options = null)
        => new SftpFileSystemEnumerable<T>(_sftpClient, RemotePath.ResolvePath([_workingDirectory, path]), transform, options ?? DefaultEnumerationOptions);

    public ValueTask CreateDirectoryAsync(string path, CancellationToken cancellationToken)
        => CreateDirectoryAsync(path, createParents: false, DefaultCreateDirectoryPermissions, cancellationToken);

    public async ValueTask CreateDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.CreateDirectoryAsync(_workingDirectory, path, createParents, permissions, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask CreateNewDirectoryAsync(string path, CancellationToken cancellationToken)
        => CreateNewDirectoryAsync(path, createParents: false, DefaultCreateDirectoryPermissions, cancellationToken);

    public async ValueTask CreateNewDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.CreateNewDirectoryAsync(_workingDirectory, path, createParents, permissions, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, CancellationToken cancellationToken = default)
        => UploadDirectoryEntriesAsync(localDirPath, remoteDirPath, options: null, cancellationToken);

    public async ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, UploadEntriesOptions? options, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.UploadDirectoryEntriesAsync(_workingDirectory, localDirPath, remoteDirPath, options, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, CancellationToken cancellationToken)
        => UploadFileAsync(localFilePath, remoteFilePath, overwrite: false, createPermissions: null, cancellationToken);

    public async ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite = false, UnixFilePermissions? createPermissions = default, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.UploadFileAsync(_workingDirectory, localFilePath, remoteFilePath, length: null, overwrite, createPermissions, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask UploadFileAsync(Stream source, string remoteFilePath, CancellationToken cancellationToken)
        => UploadFileAsync(source, remoteFilePath, overwrite: false, createPermissions: DefaultCreateFilePermissions, cancellationToken);

    public async ValueTask UploadFileAsync(Stream source, string remoteFilePath, bool overwrite = false, UnixFilePermissions createPermissions = DefaultCreateFilePermissions, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.UploadFileAsync(_workingDirectory, source, remoteFilePath, length: null, overwrite, createPermissions, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, CancellationToken cancellationToken = default)
        => DownloadDirectoryEntriesAsync(remoteDirPath, localDirPath, options: null, cancellationToken);

    public async ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, DownloadEntriesOptions? options, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.DownloadDirectoryEntriesAsync(_workingDirectory, remoteDirPath, localDirPath, options, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, CancellationToken cancellationToken)
        => DownloadFileAsync(remoteFilePath, localFilePath, overwrite: false, cancellationToken);

    public async ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.DownloadFileAsync(_workingDirectory, remoteFilePath, localFilePath, overwrite, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DownloadFileAsync(string remoteFilePath, Stream destination, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.DownloadFileAsync(_workingDirectory, remoteFilePath, destination, cancellationToken).ConfigureAwait(false);
    }
}
