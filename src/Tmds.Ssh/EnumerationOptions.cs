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
    public SftpFileEntryPredicate? ShouldRecurse { get; set; }
    public SftpFileEntryPredicate? ShouldInclude { get; set; }
    public string[]? ExtendedAttributes { get; set; } = [];

    // Used to implement recursive DeleteDirectory.
    // note: callback is not called for the root path itself.
    internal delegate void DirectoryCompletedCallback(ReadOnlySpan<char> name);
    internal DirectoryCompletedCallback? DirectoryCompleted { get; set; }
}