// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Options for downloading directory entries.
/// </summary>
public sealed class DownloadEntriesOptions
{
    /// <summary>
    /// Delegate for replacing invalid path characters.
    /// </summary>
    /// <param name="invalidPath">The path containing invalid characters.</param>
    /// <param name="invalidChars">Characters that are invalid on the current platform.</param>
    /// <param name="buffer">Pre-allocated buffer that may be used for returning a path.</param>
    /// <returns>The corrected path.</returns>
    public delegate ReadOnlySpan<char> ReplaceCharacters(ReadOnlySpan<char> invalidPath, ReadOnlySpan<char> invalidChars, Span<char> buffer);

    /// <summary>
    /// Gets or sets whether to overwrite existing files.
    /// </summary>
    public bool Overwrite { get; set; } = false;

    /// <summary>
    /// Gets or sets whether to include subdirectories.
    /// </summary>
    public bool IncludeSubdirectories { get; set; } = true;

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
        UnixFileTypeFilter.SymbolicLink;

    /// <summary>
    /// Gets or sets <see cref="SftpFileEntryPredicate"/> to determine if a directory should be recursed.
    /// </summary>
    public SftpFileEntryPredicate? ShouldRecurse { get; set; }

    /// <summary>
    /// Gets or sets <see cref="SftpFileEntryPredicate"/> to determine if an entry should be included.
    /// </summary>
    /// <remarks>
    /// Parent directories will be created for included entries when they don't exist yet.
    /// </remarks>
    public SftpFileEntryPredicate? ShouldInclude { get; set; }

    /// <summary>
    /// Gets or sets the delegate for replacing invalid path characters.
    /// </summary>
    public ReplaceCharacters ReplaceInvalidCharacters { get; set; } = ReplaceInvalidCharactersWithUnderscore;

    /// <summary>
    /// Gets or sets how to handle target directory creation.
    /// </summary>
    public TargetDirectoryCreation TargetDirectoryCreation { get; set; } = TargetDirectoryCreation.CreateWithParents;

    private static ReadOnlySpan<char> ReplaceInvalidCharactersWithUnderscore(ReadOnlySpan<char> invalidPath, ReadOnlySpan<char> invalidChars, Span<char> buffer)
    {
        Span<char> path = buffer.Length >= invalidPath.Length ? buffer.Slice(0, invalidPath.Length)
                                                              : new char[invalidPath.Length];

        invalidPath.CopyTo(path);
        Span<char> remainder = path;
        do
        {
            int idx = remainder.IndexOfAny(invalidChars);
            if (idx == -1)
            {
                break;
            }
            remainder[idx] = '_';
            remainder = remainder.Slice(idx + 1);
        } while (true);

        return path;
    }
}