// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

static class ReadOnlySequenceExtensions
{
    public static bool Equals<T>(this ReadOnlySequence<T> ros, ReadOnlySpan<T> span) where T : IEquatable<T>
    {
        if (ros.IsSingleSegment)
        {
            return ros.FirstSpan.SequenceEqual(span);
        }
        else
        {
            return MultiSegmentEquals(ros, span);
        }
    }

    private static bool MultiSegmentEquals<T>(this ReadOnlySequence<T> ros, ReadOnlySpan<T> span) where T : IEquatable<T>
    {
        if (ros.Length != span.Length)
        {
            return false;
        }
        while (span.Length > 0)
        {
            if (!span.StartsWith(ros.FirstSpan))
            {
                return false;
            }
            int length = ros.FirstSpan.Length;
            span = span.Slice(length);
            ros = ros.Slice(length);
        }
        return true;
    }
}
