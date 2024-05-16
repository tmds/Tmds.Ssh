// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Diagnostics.CodeAnalysis;

namespace Tmds.Ssh;

static class RemotePath
{
    public const char DirectorySeparatorChar = '/';
    private const char NullChar = '\0';
    private const string DirectorySeparatorCharAsString = "/";

    public const int MaxPathLength = 4096;
    public const int MaxNameLength = 256;

    internal static string EnsureTrailingSeparator(string path)
        => EndsInDirectorySeparator(path.AsSpan()) ? path : path + DirectorySeparatorCharAsString;

    public static string TrimEndingDirectorySeparators(string path)
    {
        var span = TrimEndingDirectorySeparators(path.AsSpan());
        return span.Length == path.Length ? path : new string(span);
    }

    public static ReadOnlySpan<char> TrimEndingDirectorySeparators(ReadOnlySpan<char> path)
    {
        while (EndsInDirectorySeparator(path) && !IsRoot(path))
        {
            path = path.Slice(0, path.Length - 1);
        }
        return path;
    }

    private static bool EndsInDirectorySeparator(ReadOnlySpan<char> path) =>
        path.Length > 0 && IsDirectorySeparator(path[path.Length - 1]);

    private static bool IsDirectorySeparator(char c)
    {
        return c == DirectorySeparatorChar;
    }

    private static bool IsRoot(ReadOnlySpan<char> path)
        => path.Length == GetRootLength(path);

    private static int GetRootLength(ReadOnlySpan<char> path)
        => path.Length > 0 && IsDirectorySeparator(path[0]) ? 1 : 0;

    public static bool IsValidFileName(ReadOnlySpan<byte> filename)
        => filename.Length > 0 &&
           filename.IndexOf((byte)DirectorySeparatorChar) == -1 &&
           filename.IndexOf((byte)NullChar) == -1;
}