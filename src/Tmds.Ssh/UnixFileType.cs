// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Unix file types.
/// </summary>
public enum UnixFileType : short
{
    /// <summary>
    /// Regular file.
    /// </summary>
    RegularFile = UnixFileTypeFilter.RegularFile << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.RegularFile,

    /// <summary>
    /// Directory.
    /// </summary>
    Directory = UnixFileTypeFilter.Directory << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.Directory,

    /// <summary>
    /// Symbolic link.
    /// </summary>
    SymbolicLink = UnixFileTypeFilter.SymbolicLink << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.SymbolicLink,

    /// <summary>
    /// Character device.
    /// </summary>
    CharacterDevice = UnixFileTypeFilter.CharacterDevice << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.CharacterDevice,

    /// <summary>
    /// Block device.
    /// </summary>
    BlockDevice = UnixFileTypeFilter.BlockDevice << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.BlockDevice,

    /// <summary>
    /// Unix domain socket.
    /// </summary>
    Socket = UnixFileTypeFilter.Socket << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.Socket,

    /// <summary>
    /// Named pipe (FIFO).
    /// </summary>
    Fifo = UnixFileTypeFilter.Fifo << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.Fifo,

    /// <summary>
    /// Unknown file type.
    /// </summary>
    WeirdFile = unchecked((short)(UnixFileTypeFilter.WeirdFile << UnixFileTypeFilterExtensions.TypeShift))
}

static class UnixFileTypeExtensions
{
    public static int GetMode(this UnixFileType type)
        => ((int)type & 0xff) << 12;
}
