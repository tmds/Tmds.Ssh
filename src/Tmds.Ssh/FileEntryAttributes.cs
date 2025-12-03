// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Attributes of a filesystem entry.
/// </summary>
public sealed class FileEntryAttributes
{
    /// <summary>
    /// Gets or sets the file length in bytes.
    /// </summary>
    public long Length { get; set; }

    /// <summary>
    /// Gets or sets the user ID.
    /// </summary>
    public int Uid { get; set; }

    /// <summary>
    /// Gets or sets the group ID.
    /// </summary>
    public int Gid { get; set; }

    /// <summary>
    /// Gets or sets the <see cref="UnixFileType"/>.
    /// </summary>
    public UnixFileType FileType { get; set; }

    /// <summary>
    /// Gets or sets the <see cref="UnixFilePermissions"/>.
    /// </summary>
    public UnixFilePermissions Permissions { get; set; }

    /// <summary>
    /// Gets or sets the last access time.
    /// </summary>
    public DateTimeOffset LastAccessTime { get; set; }

    /// <summary>
    /// Gets or sets the last write time.
    /// </summary>
    public DateTimeOffset LastWriteTime { get; set; }

    /// <summary>
    /// Gets or sets extended attributes.
    /// </summary>
    public Dictionary<string, byte[]>? ExtendedAttributes { get; set; }
}
