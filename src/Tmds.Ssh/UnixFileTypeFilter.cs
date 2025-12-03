// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Filter for Unix file types.
/// </summary>
[Flags]
public enum UnixFileTypeFilter : byte
{
    /// <summary>
    /// Regular file.
    /// </summary>
    RegularFile = 1,

    /// <summary>
    /// Directory.
    /// </summary>
    Directory = 2,

    /// <summary>
    /// Symbolic link.
    /// </summary>
    SymbolicLink = 4,

    /// <summary>
    /// Character device.
    /// </summary>
    CharacterDevice = 8,

    /// <summary>
    /// Block device.
    /// </summary>
    BlockDevice = 16,

    /// <summary>
    /// Unix domain socket.
    /// </summary>
    Socket = 32,

    /// <summary>
    /// Named pipe (FIFO).
    /// </summary>
    Fifo = 64,

    /// <summary>
    /// Unknown file type.
    /// </summary>
    WeirdFile = 128
}

static class UnixFileTypeFilterExtensions
{
    internal const int TypeShift = 8;

    public static bool Matches(this UnixFileTypeFilter filter, UnixFileType type)
        => (((int)type >> TypeShift) & (int)filter) != 0;
}
