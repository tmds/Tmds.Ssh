// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Globalization;
using System.Text;

namespace Tmds.Ssh
{
    static class PrettyBytePrinter
    {
        internal const int BytesPerLine = 32;

        public static string ToHexString(ReadOnlySpan<byte> span)
        {
            StringBuilder sb = new StringBuilder(); // TODO: is there a public pool for these?
            Append(sb, span, offset: 0);
            return sb.ToString();
        }

        public static string ToHexString(byte[] array)
            => ToHexString(array.AsSpan());

        public static string ToHexString(ArraySegment<byte> segment)
            => ToHexString(segment.AsSpan());

        public static string ToHexString(ReadOnlySequence<byte> sequence)
        {
            if (sequence.IsSingleSegment)
            {
                return ToHexString(sequence.FirstSpan);
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

        public static string ToMultiLineString(ReadOnlySequence<byte> sequence)
        {
            StringBuilder sb = new StringBuilder(); // TODO: is there a public pool for these?
            sb.AppendLine();

            do
            {
                ReadOnlySpan<byte> firstSpan = sequence.FirstSpan;
                if (sequence.IsSingleSegment)
                {
                    AppendLines(sb, firstSpan, true);
                    return sb.ToString();
                }

                int useLength = firstSpan.Length;
                if (useLength < BytesPerLine)
                {
                    useLength = (int)Math.Min(BytesPerLine, useLength);
                    Span<byte> lineBuffer = stackalloc byte[useLength];
                    firstSpan.CopyTo(lineBuffer);
                    AppendLine(sb, lineBuffer, useLength == sequence.Length);
                }
                else
                {
                    useLength -= (useLength % BytesPerLine);
                    AppendLines(sb, firstSpan.Slice(0, useLength), useLength == sequence.Length);
                }
                sequence = sequence.Slice(useLength);
            } while (true);
        }

        public static string ToHexString(Sequence sequence)
            => ToHexString(sequence.AsReadOnlySequence());

        private static void Append(StringBuilder sb, ReadOnlySpan<byte> span, long offset)
        {
            foreach (var b in span)
            {
                sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }
        }

        private static void AppendLines(StringBuilder sb, ReadOnlySpan<byte> span, bool final)
        {
            while (!span.IsEmpty)
            {
                ReadOnlySpan<byte> line = span;
                if (line.Length > BytesPerLine)
                {
                    line = line.Slice(0, BytesPerLine);
                }
                AppendLine(sb, line, final && line.Length == span.Length);

                span = span.Slice(line.Length);
            }
        }

        private static void AppendLine(StringBuilder sb, ReadOnlySpan<byte> line, bool final)
        {
            foreach (var b in line)
            {
                sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }

            for (int i = line.Length; i < BytesPerLine; i++)
            {
                sb.Append("  ");
            }

            sb.Append("  |");

            foreach (var b in line)
            {
                char c = (char)b;
                bool printable = c < 127 && c >= 32;
                sb.Append(printable ? c : '.');
            }

            if (final)
            {
                sb.Append("|");
            }
            else
            {
                sb.AppendLine("|");
            }
        }
    }
}