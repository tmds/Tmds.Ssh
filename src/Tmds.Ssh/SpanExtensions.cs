// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Numerics;

namespace Tmds.Ssh
{
    static class SpanExtensions
    {
        public static BigInteger ToBigInteger(this ReadOnlySpan<byte> span)
        {
            // isUnsigned: false -> don't prepend with zero.
            // isBigEndian: true -> keep the order.
            return new BigInteger(span, isUnsigned: false, isBigEndian: true);
        }

        public static BigInteger ToBigInteger(this byte[] value)
            => ToBigInteger(value.AsSpan());
    }
}
