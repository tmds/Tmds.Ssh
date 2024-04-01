// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class EnumerationOptions
{
    public bool RecurseSubdirectories { get; set; }
    public bool FollowFileLinks { get; set; } = true;
    public bool FollowDirectoryLinks { get; set; } = true;
    public UnixFileTypeFilter FileTypeFilter { get; set; } =
        UnixFileTypeFilter.RegularFile |
        UnixFileTypeFilter.Directory |
        UnixFileTypeFilter.SymbolicLink |
        UnixFileTypeFilter.CharacterDevice |
        UnixFileTypeFilter.BlockDevice |
        UnixFileTypeFilter.Socket |
        UnixFileTypeFilter.Fifo;
}