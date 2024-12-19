// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

static class ROSExtensions
{
    public static void CopyTo(this ReadOnlySequence<byte> src, Span<byte> dst, int length)
    {
        ReadOnlySpan<byte> firstSpan = src.FirstSpan;
        if (firstSpan.Length >= length)
        {
            firstSpan.Slice(0, length).CopyTo(dst);
        }
        else
        {
            src.Slice(0, length).CopyTo(dst);
        }
    }
}
