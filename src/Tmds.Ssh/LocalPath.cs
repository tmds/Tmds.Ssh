// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

static class LocalPath
{
    public static char[] InvalidLocalPathChars =
        OperatingSystem.IsWindows() ? Path.GetInvalidFileNameChars().Where(c => c != RemotePath.DirectorySeparatorChar).ToArray()
                                    : Array.Empty<char>();

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