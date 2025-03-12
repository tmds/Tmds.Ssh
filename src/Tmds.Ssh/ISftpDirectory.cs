// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public interface ISftpDirectory
{
    string Path { get; }

    ISftpDirectory GetDirectory(string path);

    ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default);
    ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default);
    ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default);
    ValueTask DeleteFileAsync(string path, CancellationToken cancellationToken = default);
    ValueTask DeleteDirectoryAsync(string path, CancellationToken cancellationToken = default);
    ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default);
    ValueTask CopyFileAsync(string sourcePath, string destinationPath, bool overwrite = false, CancellationToken cancellationToken = default);
    ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, bool followLinks = true, CancellationToken cancellationToken = default);
    ValueTask SetAttributesAsync(
        string path,
        UnixFilePermissions? permissions = default,
        (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
        long? length = default,
        (int Uid, int Gid)? ids = default,
        IEnumerable<KeyValuePair<string, Memory<byte>>>? extendedAttributes = default,
        CancellationToken cancellationToken = default);
    ValueTask<string> GetLinkTargetAsync(string linkPath, CancellationToken cancellationToken = default);
    ValueTask<string> GetRealPathAsync(string path, CancellationToken cancellationToken = default);
    ValueTask CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default);
    IAsyncEnumerable<T> GetDirectoryEntriesAsync<T>(string path, SftpFileEntryTransform<T> transform, EnumerationOptions? options = null);
    ValueTask CreateDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = SftpClient.DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default);
    ValueTask CreateNewDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = SftpClient.DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default);
    ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, UploadEntriesOptions? options, CancellationToken cancellationToken = default);
    ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite = false, UnixFilePermissions? createPermissions = default, CancellationToken cancellationToken = default);
    ValueTask UploadFileAsync(Stream source, string remoteFilePath, bool overwrite = false, UnixFilePermissions createPermissions = SftpClient.DefaultCreateFilePermissions, CancellationToken cancellationToken = default);
    ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, DownloadEntriesOptions? options, CancellationToken cancellationToken = default);
    ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, bool overwrite = false, CancellationToken cancellationToken = default);
    ValueTask DownloadFileAsync(string remoteFilePath, Stream destination, CancellationToken cancellationToken = default);
}

public static class SftpDirectoryExtensions
{
    public static ValueTask<SftpFile> OpenOrCreateFileAsync(this ISftpDirectory directory, string path, FileAccess access, CancellationToken cancellationToken = default)
        => directory.OpenOrCreateFileAsync(path, access, options: null, cancellationToken);

    public static ValueTask<SftpFile> CreateNewFileAsync(this ISftpDirectory directory, string path, FileAccess access, CancellationToken cancellationToken = default)
        => directory.CreateNewFileAsync(path, access, options: null, cancellationToken);

    public static ValueTask<SftpFile?> OpenFileAsync(this ISftpDirectory directory, string path, FileAccess access, CancellationToken cancellationToken = default)
        => directory.OpenFileAsync(path, access, options: null, cancellationToken);

    public static IAsyncEnumerable<(string Path, FileEntryAttributes Attributes)> GetDirectoryEntriesAsync(this ISftpDirectory directory, string path, EnumerationOptions? options = null)
        => directory.GetDirectoryEntriesAsync(path, (ref SftpFileEntry entry) => (entry.ToPath(), entry.ToAttributes()), options);

    public static ValueTask CreateDirectoryAsync(this ISftpDirectory directory, string path, CancellationToken cancellationToken)
        => directory.CreateDirectoryAsync(path, createParents: false, SftpClient.DefaultCreateDirectoryPermissions, cancellationToken);

    public static ValueTask CreateNewDirectoryAsync(this ISftpDirectory directory, string path, CancellationToken cancellationToken)
        => directory.CreateNewDirectoryAsync(path, createParents: false, SftpClient.DefaultCreateDirectoryPermissions, cancellationToken);

    public static ValueTask UploadDirectoryEntriesAsync(this ISftpDirectory directory, string localDirPath, string remoteDirPath, CancellationToken cancellationToken = default)
        => directory.UploadDirectoryEntriesAsync(localDirPath, remoteDirPath, options: null, cancellationToken);

    public static ValueTask UploadFileAsync(this ISftpDirectory directory, string localFilePath, string remoteFilePath, CancellationToken cancellationToken)
        => directory.UploadFileAsync(localFilePath, remoteFilePath, overwrite: false, createPermissions: null, cancellationToken);

    public static ValueTask UploadFileAsync(this ISftpDirectory directory, Stream source, string remoteFilePath, CancellationToken cancellationToken)
        => directory.UploadFileAsync(source, remoteFilePath, overwrite: false, createPermissions: SftpClient.DefaultCreateFilePermissions, cancellationToken);

    public static ValueTask DownloadDirectoryEntriesAsync(this ISftpDirectory directory, string remoteDirPath, string localDirPath, CancellationToken cancellationToken = default)
        => directory.DownloadDirectoryEntriesAsync(remoteDirPath, localDirPath, options: null, cancellationToken);

    public static ValueTask DownloadFileAsync(this ISftpDirectory directory, string remoteFilePath, string localFilePath, CancellationToken cancellationToken)
        => directory.DownloadFileAsync(remoteFilePath, localFilePath, overwrite: false, cancellationToken);

}