// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

static class LocalPath
{
    private static ReadOnlySpan<char> WindowsInvalidLocalPathChars =>
    [
        '\"', '<', '>', '|',// '\0',
        (char)1, (char)2, (char)3, (char)4, (char)5, (char)6, (char)7, (char)8, (char)9, (char)10,
        (char)11, (char)12, (char)13, (char)14, (char)15, (char)16, (char)17, (char)18, (char)19, (char)20,
        (char)21, (char)22, (char)23, (char)24, (char)25, (char)26, (char)27, (char)28, (char)29, (char)30,
        (char)31, ':', '*', '?', '\\',// '/'
    ];

    internal static ReadOnlySpan<char> InvalidLocalPathChars =>
        OperatingSystem.IsWindows() ? WindowsInvalidLocalPathChars
                                    : default;

    public const int MaxPathLength = 4096;
    public const int MaxNameLength = 256;

    public static string EnsureTrailingSeparator(string path)
        => EndsInDirectorySeparator(path.AsSpan()) ? path : path + Path.DirectorySeparatorChar;

    public static bool EndsInDirectorySeparator(ReadOnlySpan<char> path) =>
        path.Length > 0 && IsDirectorySeparator(path[path.Length - 1]);

    public static bool IsDirectorySeparator(char c)
        => c == Path.DirectorySeparatorChar || c == Path.AltDirectorySeparatorChar;

    public static bool IsRemotePathValidLocalSubPath(ReadOnlySpan<char> validRemotePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            return true;
        }
        return validRemotePath.IndexOfAny(InvalidLocalPathChars) < 0;
    }
}