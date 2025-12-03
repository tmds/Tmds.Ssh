// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Options for enumerating directory entries.
/// </summary>
public sealed class EnumerationOptions
{
    /// <summary>
    /// Gets or sets whether to recurse subdirectories.
    /// </summary>
    public bool RecurseSubdirectories { get; set; }

    /// <summary>
    /// Gets or sets whether to follow file symbolic links.
    /// </summary>
    public bool FollowFileLinks { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to follow directory symbolic links.
    /// </summary>
    public bool FollowDirectoryLinks { get; set; } = true;

    /// <summary>
    /// Gets or sets the <see cref="UnixFileTypeFilter"/>.
    /// </summary>
    public UnixFileTypeFilter FileTypeFilter { get; set; } =
        UnixFileTypeFilter.RegularFile |
        UnixFileTypeFilter.Directory |
        UnixFileTypeFilter.SymbolicLink |
        UnixFileTypeFilter.CharacterDevice |
        UnixFileTypeFilter.BlockDevice |
        UnixFileTypeFilter.Socket |
        UnixFileTypeFilter.Fifo;

    /// <summary>
    /// Gets or sets <see cref="SftpFileEntryPredicate"/> to determine if a directory should be recursed.
    /// </summary>
    public SftpFileEntryPredicate? ShouldRecurse { get; set; }

    /// <summary>
    /// Gets or sets <see cref="SftpFileEntryPredicate"/> to determine if an entry should be included.
    /// </summary>
    public SftpFileEntryPredicate? ShouldInclude { get; set; }

    /// <summary>
    /// Gets or sets extended attributes to retrieve.
    /// </summary>
    public string[]? ExtendedAttributes { get; set; } = [];

    // Used to implement recursive DeleteDirectory.
    // note: callback is not called for the root path itself.
    internal delegate void DirectoryCompletedCallback(ReadOnlySpan<char> name);
    internal DirectoryCompletedCallback? DirectoryCompleted { get; set; }
}