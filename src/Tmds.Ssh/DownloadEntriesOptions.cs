// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh;

public sealed class DownloadEntriesOptions
{
    public delegate ReadOnlySpan<char> ReplaceCharacters(Span<char> buffer, int pathLength, ReadOnlySpan<char> invalidChars);

    public bool Overwrite { get; set; } = false;
    public bool RecurseSubdirectories { get; set; } = true;
    public bool FollowFileLinks { get; set; } = true;
    public bool FollowDirectoryLinks { get; set; } = true;
    public UnixFileTypeFilter FileTypeFilter { get; set; } =
        UnixFileTypeFilter.RegularFile |
        UnixFileTypeFilter.Directory |
        UnixFileTypeFilter.SymbolicLink;
    public SftpFileEntryPredicate? ShouldRecurse { get; set; }
    public SftpFileEntryPredicate? ShouldInclude { get; set; }
    public ReplaceCharacters ReplaceInvalidCharacters { get; set; } = ReplaceInvalidCharactersWithUnderscore;

    private static ReadOnlySpan<char> ReplaceInvalidCharactersWithUnderscore(Span<char> buffer, int pathLength, ReadOnlySpan<char> invalidChars)
    {
        Span<char> remainder = buffer.Slice(0, pathLength);
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
        return buffer.Slice(0, pathLength);
    }
}