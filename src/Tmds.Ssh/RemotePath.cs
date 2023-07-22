// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Diagnostics.CodeAnalysis;

namespace Tmds.Ssh;

static class RemotePath
{
    public const char DirectorySeparatorChar = '/';
    private const string DirectorySeparatorCharAsString = "/";

    public const int MaxPathLength = 4096;
    public const int MaxNameLength = 256;

    internal static string EnsureTrailingSeparator(string path)
        => EndsInDirectorySeparator(path.AsSpan()) ? path : path + DirectorySeparatorCharAsString;

    [return: NotNullIfNotNull(nameof(path))]
    public static string? TrimEndingDirectorySeparator(string? path) =>
        EndsInDirectorySeparator(path) && !IsRoot(path.AsSpan()) ?
            path!.Substring(0, path.Length - 1) :
            path;

    public static ReadOnlySpan<char> TrimEndingDirectorySeparator(ReadOnlySpan<char> path) =>
            EndsInDirectorySeparator(path) && !IsRoot(path) ?
                path.Slice(0, path.Length - 1) :
                path;

    private static bool EndsInDirectorySeparator(ReadOnlySpan<char> path) =>
        path.Length > 0 && IsDirectorySeparator(path[path.Length - 1]);

    private static bool IsDirectorySeparator(char c)
    {
        return c == DirectorySeparatorChar;
    }

    private static bool IsRoot(ReadOnlySpan<char> path)
        => path.Length == GetRootLength(path);

    private static int GetRootLength(ReadOnlySpan<char> path)
    {
        return path.Length > 0 && IsDirectorySeparator(path[0]) ? 1 : 0;
    }
}