// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Globalization;
using System.Text;

namespace Tmds.Ssh
{
    static class PrettyBytePrinter
    {
        public static string ToString(ReadOnlySpan<byte> span)
        {
            StringBuilder sb = new StringBuilder(); // TODO: is there a public pool for these?
            Append(sb, span, offset: 0);
            return sb.ToString();
        }

        public static string ToString(byte[] array)
            => ToString(array.AsSpan());

        public static string ToString(ArraySegment<byte> segment)
            => ToString(segment.AsSpan());

        public static string ToString(ReadOnlySequence<byte> sequence)
        {
            if (sequence.IsSingleSegment)
            {
                return ToString(sequence.FirstSpan);
            }
            else
            {
                StringBuilder sb = new StringBuilder(); // TODO: is there a public pool for these?
                long offset = 0;
                foreach (var segment in sequence)
                {
                    Append(sb, segment.Span, offset);
                    offset += segment.Length;
                }
                return sb.ToString();
            }
        }

        public static string ToString(Sequence sequence)
            => ToString(sequence.AsReadOnlySequence());

        private static void Append(StringBuilder sb, ReadOnlySpan<byte> span, long offset)
        {
            sb.Append('[');
            foreach (var b in span)
            {
                sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }
            sb.Append(']');
        }
    }
}