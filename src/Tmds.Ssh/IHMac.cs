// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;

namespace Tmds.Ssh;

static class HMacExtensions
{
    public static void AppendData(this IHMac mac, ReadOnlySequence<byte> sequence)
    {
        if (sequence.IsSingleSegment)
        {
            mac.AppendData(sequence.FirstSpan);
        }
        else
        {
            foreach (var segment in sequence)
            {
                mac.AppendData(segment.Span);
            }
        }
    }
}

interface IHMac : IDisposable
{
    int HashSize { get; }
    void AppendData(ReadOnlySpan<byte> data);
    void AppendHashToSequenceAndReset(Sequence output);
    bool CheckHashAndReset(ReadOnlySpan<byte> hash);
}
