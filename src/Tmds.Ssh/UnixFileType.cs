// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public enum UnixFileType : short
{
    RegularFile = UnixFileTypeFilter.RegularFile << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.RegularFile,
    Directory = UnixFileTypeFilter.Directory << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.Directory,
    SymbolicLink = UnixFileTypeFilter.SymbolicLink << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.SymbolicLink,
    CharacterDevice = UnixFileTypeFilter.CharacterDevice << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.CharacterDevice,
    BlockDevice = UnixFileTypeFilter.BlockDevice << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.BlockDevice,
    Socket = UnixFileTypeFilter.Socket << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.Socket,
    Fifo = UnixFileTypeFilter.Fifo << UnixFileTypeFilterExtensions.TypeShift | UnixFileTypeByte.Fifo,
    WeirdFile = unchecked((short)(UnixFileTypeFilter.WeirdFile << UnixFileTypeFilterExtensions.TypeShift))
}

static class UnixFileTypeExtensions
{
    public static int GetMode(this UnixFileType type)
        => ((int)type & 0xff) << 12;
}
