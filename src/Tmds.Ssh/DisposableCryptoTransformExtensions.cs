// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh
{
    static class DisposableCryptoTransformExtensions
    {
        public static void Transform(this IDisposableCryptoTransform transform, ReadOnlySequence<byte> data, Sequence output)
            => transform.Transform(default, data, default, output);
    }
}