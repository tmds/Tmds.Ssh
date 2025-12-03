// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Options for opening files.
/// </summary>
public sealed class FileOpenOptions
{
    /// <summary>
    /// Gets or sets the <see cref="OpenMode"/> which controls whether to append or truncate the file.
    /// </summary>
    public OpenMode OpenMode { get; set; } = OpenMode.Default;

    /// <summary>
    /// Gets or sets <see cref="UnixFilePermissions"/> for newly created files.
    /// </summary>
    public UnixFilePermissions CreatePermissions { get; set; } = SftpClient.DefaultCreateFilePermissions;

    /// <summary>
    /// Gets or sets whether to cache file length.
    /// </summary>
    public bool CacheLength { get; set; } = false;

    /// <summary>
    /// Gets or sets whether the file <see cref="Stream"/> should support seeking.
    /// </summary>
    public bool Seekable { get; set; } = false;
}