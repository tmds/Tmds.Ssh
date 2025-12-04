// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Interface for SFTP directory operations.
/// </summary>
public interface ISftpDirectory
{
    /// <summary>
    /// Gets the directory path.
    /// </summary>
    string Path { get; }

    /// <summary>
    /// Gets an SftpDirectory for the specified path.
    /// </summary>
    /// <param name="path">The directory path.</param>
    /// <returns>An <see cref="ISftpDirectory"/> for the specified path.</returns>
    ISftpDirectory GetDirectory(string path);

    /// <summary>
    /// Opens an existing file or creates it when it does not yet exist.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="access">The <see cref="FileAccess"/> mode.</param>
    /// <param name="options"><see cref="FileOpenOptions"/> for opening the file.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns><see cref="SftpFile"/> instance for the opened file.</returns>
    ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new file. Fails if it already exists.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="access">The <see cref="FileAccess"/> mode.</param>
    /// <param name="options"><see cref="FileOpenOptions"/> for creating the file.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns><see cref="SftpFile"/> instance for the opened file.</returns>
    ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default);

    /// <summary>
    /// Opens an existing file.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="access">The <see cref="FileAccess"/> mode.</param>
    /// <param name="options"><see cref="FileOpenOptions"/> for opening the file.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns><see cref="SftpFile"/> instance for the opened file, or <see langword="null"/> if it doesn't exist.</returns>
    ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a file.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask DeleteFileAsync(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a directory.
    /// </summary>
    /// <param name="path">The directory path.</param>
    /// <param name="recursive">Whether to delete directories recursively.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask DeleteDirectoryAsync(string path, bool recursive = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Renames or moves a file or directory.
    /// </summary>
    /// <param name="oldPath">The current path.</param>
    /// <param name="newPath">The new path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Copies a file.
    /// </summary>
    /// <param name="sourcePath">The source file path.</param>
    /// <param name="destinationPath">The destination file path.</param>
    /// <param name="overwrite">Whether to overwrite an existing file.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask CopyFileAsync(string sourcePath, string destinationPath, bool overwrite = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets file or directory attributes.
    /// </summary>
    /// <param name="path">The file or directory path.</param>
    /// <param name="followLinks">Whether to follow symbolic links.</param>
    /// <param name="filter">Extended attributes to include.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The <see cref="FileEntryAttributes"/>, or <see langword="null"/> if not found.</returns>
    ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, bool followLinks, string[]? filter, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets file or directory attributes.
    /// </summary>
    /// <param name="path">The file or directory path.</param>
    /// <param name="permissions"><see cref="UnixFilePermissions"/> to set.</param>
    /// <param name="times">Access and modification times to set.</param>
    /// <param name="length">File length to set (truncates or extends).</param>
    /// <param name="ids">User and group IDs to set.</param>
    /// <param name="extendedAttributes">Extended attributes to set.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask SetAttributesAsync(
        string path,
        UnixFilePermissions? permissions = default,
        (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
        long? length = default,
        (int Uid, int Gid)? ids = default,
        IEnumerable<KeyValuePair<string, Memory<byte>>>? extendedAttributes = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the target of a symbolic link.
    /// </summary>
    /// <param name="linkPath">The symbolic link path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The target path.</returns>
    ValueTask<string> GetLinkTargetAsync(string linkPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves a path to its canonical absolute path.
    /// </summary>
    /// <param name="path">The path to resolve.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The canonical absolute path.</returns>
    ValueTask<string> GetRealPathAsync(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a symbolic link.
    /// </summary>
    /// <param name="linkPath">The symbolic link path to create.</param>
    /// <param name="targetPath">The target path the link points to.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enumerates directory entries asynchronously.
    /// </summary>
    /// <typeparam name="T">Result type to transform entries to.</typeparam>
    /// <param name="path">The directory path to enumerate.</param>
    /// <param name="transform"><see cref="SftpFileEntryTransform{T}"/> function for each entry.</param>
    /// <param name="options"><see cref="EnumerationOptions"/> for enumeration.</param>
    /// <returns>An async enumerable of transformed entries.</returns>
    IAsyncEnumerable<T> GetDirectoryEntriesAsync<T>(string path, SftpFileEntryTransform<T> transform, EnumerationOptions? options = null);

    /// <summary>
    /// Creates a directory. Does not fail if it already exists.
    /// </summary>
    /// <param name="path">The directory path.</param>
    /// <param name="createParents">Whether to create parent directories.</param>
    /// <param name="permissions"><see cref="UnixFilePermissions"/> used when a new directory is created.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask CreateDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = SftpClient.DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new directory. Fails if it already exists.
    /// </summary>
    /// <param name="path">The directory path.</param>
    /// <param name="createParents">Whether to create parent directories.</param>
    /// <param name="permissions"><see cref="UnixFilePermissions"/> for the new directory.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask CreateNewDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = SftpClient.DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default);

    /// <summary>
    /// Uploads directory entries.
    /// </summary>
    /// <param name="localDirPath">The local directory path.</param>
    /// <param name="remoteDirPath">The remote directory path.</param>
    /// <param name="options"><see cref="UploadEntriesOptions"/> for the upload operation.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, UploadEntriesOptions? options, CancellationToken cancellationToken = default);

    /// <summary>
    /// Uploads a file.
    /// </summary>
    /// <param name="localFilePath">The local file path.</param>
    /// <param name="remoteFilePath">The remote file path.</param>
    /// <param name="overwrite">Whether to overwrite an existing file.</param>
    /// <param name="createPermissions"><see cref="UnixFilePermissions"/> when a new file is created.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite = false, UnixFilePermissions? createPermissions = default, CancellationToken cancellationToken = default);

    /// <summary>
    /// Uploads a file from a <see cref="Stream"/>.
    /// </summary>
    /// <param name="source">The source <see cref="Stream"/>.</param>
    /// <param name="remoteFilePath">The remote file path.</param>
    /// <param name="overwrite">Whether to overwrite an existing file.</param>
    /// <param name="createPermissions"><see cref="UnixFilePermissions"/> when a new file is created.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask UploadFileAsync(Stream source, string remoteFilePath, bool overwrite = false, UnixFilePermissions createPermissions = SftpClient.DefaultCreateFilePermissions, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads directory entries.
    /// </summary>
    /// <param name="remoteDirPath">The remote directory path.</param>
    /// <param name="localDirPath">The local directory path.</param>
    /// <param name="options"><see cref="DownloadEntriesOptions"/> for the download operation.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, DownloadEntriesOptions? options, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads a file.
    /// </summary>
    /// <param name="remoteFilePath">The remote file path.</param>
    /// <param name="localFilePath">The local file path.</param>
    /// <param name="overwrite">Whether to overwrite an existing file.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, bool overwrite = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads a file to a <see cref="Stream"/>.
    /// </summary>
    /// <param name="remoteFilePath">The remote file path.</param>
    /// <param name="destination">The destination <see cref="Stream"/>.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask DownloadFileAsync(string remoteFilePath, Stream destination, CancellationToken cancellationToken = default);
}

/// <summary>
/// Extension methods for ISftpDirectory.
/// </summary>
public static class SftpDirectoryExtensions
{
    /// <summary>
    /// Opens an existing file or creates it when it does not yet exist.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="path">The file path.</param>
    /// <param name="access">The <see cref="FileAccess"/> mode.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns><see cref="SftpFile"/> instance for the opened file.</returns>
    public static ValueTask<SftpFile> OpenOrCreateFileAsync(this ISftpDirectory directory, string path, FileAccess access, CancellationToken cancellationToken = default)
        => directory.OpenOrCreateFileAsync(path, access, options: null, cancellationToken);

    /// <summary>
    /// Creates a new file. Fails if it already exists.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="path">The file path.</param>
    /// <param name="access">The <see cref="FileAccess"/> mode.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns><see cref="SftpFile"/> instance for the opened file.</returns>
    public static ValueTask<SftpFile> CreateNewFileAsync(this ISftpDirectory directory, string path, FileAccess access, CancellationToken cancellationToken = default)
        => directory.CreateNewFileAsync(path, access, options: null, cancellationToken);

    /// <summary>
    /// Opens an existing file.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="path">The file path.</param>
    /// <param name="access">The <see cref="FileAccess"/> mode.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>An <see cref="SftpFile"/> for the opened file, or <see langword="null"/> if it doesn't exist.</returns>
    public static ValueTask<SftpFile?> OpenFileAsync(this ISftpDirectory directory, string path, FileAccess access, CancellationToken cancellationToken = default)
        => directory.OpenFileAsync(path, access, options: null, cancellationToken);

    /// <summary>
    /// Enumerates directory entries asynchronously.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="path">The directory path to enumerate.</param>
    /// <param name="options"><see cref="EnumerationOptions"/> for enumeration.</param>
    /// <returns>An async enumerable of path and <see cref="FileEntryAttributes"/> tuples.</returns>
    public static IAsyncEnumerable<(string Path, FileEntryAttributes Attributes)> GetDirectoryEntriesAsync(this ISftpDirectory directory, string path, EnumerationOptions? options = null)
        => directory.GetDirectoryEntriesAsync(path, (ref SftpFileEntry entry) => (entry.ToPath(), entry.ToAttributes()), options);

    /// <summary>
    /// Creates a directory. Does not fail if it already exists.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="path">The directory path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public static ValueTask CreateDirectoryAsync(this ISftpDirectory directory, string path, CancellationToken cancellationToken)
        => directory.CreateDirectoryAsync(path, createParents: false, SftpClient.DefaultCreateDirectoryPermissions, cancellationToken);

    /// <summary>
    /// Creates a new directory. Fails if it already exists.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="path">The directory path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public static ValueTask CreateNewDirectoryAsync(this ISftpDirectory directory, string path, CancellationToken cancellationToken)
        => directory.CreateNewDirectoryAsync(path, createParents: false, SftpClient.DefaultCreateDirectoryPermissions, cancellationToken);

    /// <summary>
    /// Uploads directory entries.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="localDirPath">The local directory path.</param>
    /// <param name="remoteDirPath">The remote directory path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public static ValueTask UploadDirectoryEntriesAsync(this ISftpDirectory directory, string localDirPath, string remoteDirPath, CancellationToken cancellationToken = default)
        => directory.UploadDirectoryEntriesAsync(localDirPath, remoteDirPath, options: null, cancellationToken);

    /// <summary>
    /// Uploads a file.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="localFilePath">The local file path.</param>
    /// <param name="remoteFilePath">The remote file path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public static ValueTask UploadFileAsync(this ISftpDirectory directory, string localFilePath, string remoteFilePath, CancellationToken cancellationToken)
        => directory.UploadFileAsync(localFilePath, remoteFilePath, overwrite: false, createPermissions: null, cancellationToken);

    /// <summary>
    /// Uploads a file from a <see cref="Stream"/>.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="source">The source <see cref="Stream"/>.</param>
    /// <param name="remoteFilePath">The remote file path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public static ValueTask UploadFileAsync(this ISftpDirectory directory, Stream source, string remoteFilePath, CancellationToken cancellationToken)
        => directory.UploadFileAsync(source, remoteFilePath, overwrite: false, createPermissions: SftpClient.DefaultCreateFilePermissions, cancellationToken);

    /// <summary>
    /// Downloads directory entries.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="remoteDirPath">The remote directory path.</param>
    /// <param name="localDirPath">The local directory path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public static ValueTask DownloadDirectoryEntriesAsync(this ISftpDirectory directory, string remoteDirPath, string localDirPath, CancellationToken cancellationToken = default)
        => directory.DownloadDirectoryEntriesAsync(remoteDirPath, localDirPath, options: null, cancellationToken);

    /// <summary>
    /// Downloads a file.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="remoteFilePath">The remote file path.</param>
    /// <param name="localFilePath">The local file path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public static ValueTask DownloadFileAsync(this ISftpDirectory directory, string remoteFilePath, string localFilePath, CancellationToken cancellationToken)
        => directory.DownloadFileAsync(remoteFilePath, localFilePath, overwrite: false, cancellationToken);

    /// <summary>
    /// Gets file or directory attributes.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="path">The file or directory path.</param>
    /// <param name="followLinks">Whether to follow symbolic links.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The <see cref="FileEntryAttributes"/>, or <see langword="null"/> if not found.</returns>
    public static ValueTask<FileEntryAttributes?> GetAttributesAsync(this ISftpDirectory directory, string path, bool followLinks = true, CancellationToken cancellationToken = default)
        => directory.GetAttributesAsync(path, followLinks, [], cancellationToken);

    /// <summary>
    /// Gets file or directory attributes.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="path">The file or directory path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The <see cref="FileEntryAttributes"/>, or <see langword="null"/> if not found.</returns>
    public static ValueTask<FileEntryAttributes?> GetAttributesAsync(this ISftpDirectory directory, string path, CancellationToken cancellationToken)
        => directory.GetAttributesAsync(path, followLinks: true, [], cancellationToken);

    /// <summary>
    /// Deletes a directory.
    /// </summary>
    /// <param name="directory">The working directory.</param>
    /// <param name="path">The directory path.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public static ValueTask DeleteDirectoryAsync(this ISftpDirectory directory, string path, CancellationToken cancellationToken)
        => directory.DeleteDirectoryAsync(path, recursive: false, cancellationToken);

}