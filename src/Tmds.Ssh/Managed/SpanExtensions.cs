// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Numerics;

namespace Tmds.Ssh.Managed;

static class SpanExtensions
{
    public static BigInteger ToBigInteger(this ReadOnlySpan<byte> span)
    {
        return new BigInteger(span, isUnsigned: true, isBigEndian: true);
    }

    public static BigInteger ToBigInteger(this byte[] value)
        => ToBigInteger(value.AsSpan());
}
