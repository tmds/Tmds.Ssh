// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;

namespace Tmds.Ssh;

static class LocalPath
{
    public const char DirectorySeparatorChar = '\\';
    public const char AltDirectorySeparatorChar = '\\';
    private const string DirectorySeparatorCharAsString = "/";

    public const int MaxPathLength = 4096;
    public const int MaxNameLength = 256;

    public static string EnsureTrailingSeparator(string path)
        => EndsInDirectorySeparator(path.AsSpan()) ? path : path + DirectorySeparatorCharAsString;

    public static bool EndsInDirectorySeparator(ReadOnlySpan<char> path) =>
        path.Length > 0 && IsDirectorySeparator(path[path.Length - 1]);

    public static bool IsDirectorySeparator(char c)
    {
        return c == DirectorySeparatorChar || c == AltDirectorySeparatorChar;
    }
}