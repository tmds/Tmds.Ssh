// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class DownloadEntriesOptions
{
    public delegate ReadOnlySpan<char> ReplaceCharacters(ReadOnlySpan<char> invalidPath, ReadOnlySpan<char> invalidChars, Span<char> buffer);

    public bool Overwrite { get; set; } = false;
    public bool IncludeSubdirectories { get; set; } = true;
    public bool FollowFileLinks { get; set; } = true;
    public bool FollowDirectoryLinks { get; set; } = true;
    public UnixFileTypeFilter FileTypeFilter { get; set; } =
        UnixFileTypeFilter.RegularFile |
        UnixFileTypeFilter.Directory |
        UnixFileTypeFilter.SymbolicLink;
    public SftpFileEntryPredicate? ShouldRecurse { get; set; }
    public SftpFileEntryPredicate? ShouldInclude { get; set; }
    public ReplaceCharacters ReplaceInvalidCharacters { get; set; } = ReplaceInvalidCharactersWithUnderscore;

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