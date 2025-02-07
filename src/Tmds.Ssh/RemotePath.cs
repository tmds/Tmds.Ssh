// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using System.Text;

namespace Tmds.Ssh;

static class RemotePath
{
    public const char DirectorySeparatorChar = '/';
    private const char NullChar = '\0';
    private const string DirectorySeparatorCharAsString = "/";

    public const int MaxPathLength = 4096;
    public const int MaxNameLength = 256;
    private const int StackallocPathLength = 256;

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

    public static bool EndsInDirectorySeparator(ReadOnlySpan<char> path) =>
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

    public static string ResolvePath(ReadOnlySpan<string> paths)
    {
        int maxSize = 0;
        int firstComponent = 0;

        for (int i = 0; i < paths.Length; i++)
        {
            ArgumentNullException.ThrowIfNull(paths[i], nameof(paths));

            if (paths[i].Length == 0 || paths[i].SequenceEqual("."))
            {
                continue;
            }

            if (paths[i][0] == '/')
            {
                firstComponent = i;
                maxSize = paths[i].Length;
            }
            else
            {
                maxSize += paths[i].Length;
            }

            if (paths[i][^1] != '/')
                maxSize++;
        }

        var builder = new ValueStringBuilder(stackalloc char[RemotePath.StackallocPathLength]);
        builder.EnsureCapacity(maxSize);

        string? firstUsed = null;
        string? lastUsed = null;
        for (int i = firstComponent; i < paths.Length; i++)
        {
            string path = paths[i];
            if (path.Length == 0 || path.SequenceEqual("."))
            {
                continue;
            }

            firstUsed ??= path;
            lastUsed = path;

            if (builder.Length == 0)
            {
                builder.Append(path);
            }
            else
            {
                if (builder[^1] != '/')
                {
                    builder.Append('/');
                }

                builder.Append(path);
            }
        }

        if (firstUsed is null)
        {
            return "";
        }

        Span<char> chars = builder.AsSpan();
        chars = TrimDirectorySegments(chars);

        // Don't allocate when we've used a single string and it didn't need trimming.
        string output =
            ReferenceEquals(firstUsed, lastUsed) && chars.Length == firstUsed.Length
                ? firstUsed
                : chars.ToString();

        builder.Dispose();

        return output;
    }

    private static Span<char> TrimDirectorySegments(Span<char> span)
    {
        Debug.Assert(span.Length > 0);

        // Write the trimmed path in place.
        ValueStringBuilder sb = new(span);

        if (span[0] == '/')
        {
            sb.Append('/');
            span = span.Slice(1);
        }

        while (span.Length > 0)
        {
            // Set segment to everything before the first '/' and,
            // span to what is after it.
            ReadOnlySpan<char> segment;
            int separatorPos = span.IndexOf('/');
            if (separatorPos == -1)
            {
                segment = span;
                span = default;
            }
            else
            {
                segment = span.Slice(0, separatorPos);
                span = span.Slice(separatorPos + 1);
            }

            if (segment.Length == 0 || segment.SequenceEqual(".")) // empty segment or '.'.
            { }
            else if (segment.SequenceEqual(".."))
            {
                ReadOnlySpan<char> chars = sb.AsSpan();
                if (chars.Length == 0)
                {
                    // '' + '..' -> '..'
                    sb.Append("..");
                }
                else if (chars.EndsWith("..") && (chars.Length == 2 || (chars[chars.Length - 3] == '/')))
                {
                    // '..' + '..' -> '../..'
                    // '../..' + '..' -> '../../..'
                    sb.Append('/');
                    sb.Append("..");
                }
                else
                {
                    separatorPos = chars.LastIndexOf('/');
                    if (separatorPos == -1)
                    {
                        // 'dir' + '..'-> ''
                        sb.Length = 0;
                    }
                    else if (separatorPos == 0)
                    {
                        // '/dir' + '..' -> '/'
                        sb.Length = 1;
                    }
                    else
                    {
                        // '/dir/child' + '..' -> '/dir'
                        sb.Length = separatorPos;
                    }
                }
            }
            else
            {
                // ''   + 'a' -> 'a'
                // '/'  + 'a' -> '/a'
                // '/a' + 'a' -> '/a/a'
                // 'a'  + 'a' -> 'a/a'
                if (sb.Length > 0 && sb[^1] != '/')
                {
                    sb.Append('/');
                }
                sb.Append(segment);
            }
        }

        return sb.AsSpan();
    }
}