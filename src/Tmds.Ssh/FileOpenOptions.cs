// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class FileOpenOptions
{
    public OpenMode OpenMode { get; set; } = OpenMode.Default;
    public UnixFilePermissions CreatePermissions { get; set; } = SftpClient.DefaultCreateFilePermissions;

    // This requires an additional call on open to get the length.
    public bool CacheLength { get; set; } = false;

    // Default to false since Length is not supported unless CacheLength is set.
    // Some operations (like Stream.CopyTo) expect a Length when CanSeek is set.
    // We always allow using Position, even when this is set to false.
    public bool Seekable { get; set; } = false;
}