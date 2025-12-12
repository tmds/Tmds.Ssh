// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class EncryptionCryptoTransform : IDisposableCryptoTransform
{
    private readonly IDisposable _algorithm;
    private readonly ICryptoTransform _transform;
    private readonly byte[] _blockBuffer;
    private readonly bool _encryptNotDecrypt;

    internal EncryptionCryptoTransform(IDisposable algorithm, ICryptoTransform transform, bool encryptNotDecrypt)
    {
        _algorithm = algorithm;
        _transform = transform;
        _encryptNotDecrypt = encryptNotDecrypt;

        // Fit a number of blocks into 4096 bytes.
        _blockBuffer = new byte[(4096 / _transform.InputBlockSize) * _transform.InputBlockSize];
    }

    public int BlockSize => _transform.InputBlockSize;

    public void Transform(ReadOnlySequence<byte> data, Sequence output)
        => Transform(default, data, default, output);

    private void Transform(Span<byte> prefix, ReadOnlySequence<byte> data, Span<byte> suffix, Sequence output)
    {
        do
        {
            ArraySegment<byte> inputSegment = GetArraySegmentOfBlocks(ref prefix, ref data, ref suffix);
            if (inputSegment.Count == 0)
            {
                return;
            }

            while (inputSegment.Count > 0)
            {
                // Reserve output space.
                ArraySegment<byte> outputSegment = output.AllocGetArraySegment(_transform.OutputBlockSize);

                // Trim input in case the output buffer is too small.
                int maxInput = (outputSegment.Count / _transform.OutputBlockSize) * _transform.InputBlockSize;
                if (maxInput > inputSegment.Count)
                {
                    maxInput = inputSegment.Count;
                }

                // Transform.
                int transformedOutput = Transform(inputSegment.Slice(0, maxInput), outputSegment);

                // Append to output.
                output.AppendAlloced(transformedOutput);

                // Slice input.
                int transformedInput = (transformedOutput / _transform.OutputBlockSize) * _transform.InputBlockSize;
                inputSegment = inputSegment.Slice(transformedInput);
            }
        } while (true);
    }

    private int Transform(ArraySegment<byte> input, ArraySegment<byte> output)
    {
        int transformed = _transform.TransformBlock(input.Array!, input.Offset, input.Count, output.Array!, output.Offset);
        return transformed;
    }

    private ArraySegment<byte> GetArraySegmentOfBlocks(ref Span<byte> prefix, ref ReadOnlySequence<byte> data, ref Span<byte> suffix)
    {
        int inputBlockSize = _transform.InputBlockSize;

        // No copy needed when we can get an array from the data argument.
        if (prefix.IsEmpty && data.FirstSpan.Length >= inputBlockSize)
        {
            int blocks = data.FirstSpan.Length / inputBlockSize;
            foreach (var segment in data)
            {
                bool hasArray = MemoryMarshal.TryGetArray(segment, out ArraySegment<byte> rv);
                Debug.Assert(hasArray);
                if (hasArray)
                {
                    rv = rv.Slice(0, blocks * inputBlockSize);
                    data = data.Slice(blocks * inputBlockSize);
                    return rv;
                }
                else
                {
                    break;
                }
            }
        }

        Span<byte> dst = _blockBuffer;
        if (!prefix.IsEmpty)
        {
            int maxCopy = Math.Min(dst.Length, prefix.Length);
            prefix.Slice(0, maxCopy).CopyTo(dst);
            dst = dst.Slice(maxCopy);
            prefix = prefix.Slice(maxCopy);
        }
        if (!data.IsEmpty)
        {
            int maxCopy = (int)Math.Min(dst.Length, data.Length);
            data.Slice(0, maxCopy).CopyTo(dst);
            dst = dst.Slice(maxCopy);
            data = data.Slice(maxCopy);
        }
        if (!suffix.IsEmpty)
        {
            int maxCopy = Math.Min(dst.Length, suffix.Length);
            suffix.Slice(0, maxCopy).CopyTo(dst);
            dst = dst.Slice(maxCopy);
            suffix = suffix.Slice(maxCopy);
        }

        return new ArraySegment<byte>(_blockBuffer, 0, _blockBuffer.Length - dst.Length);
    }

    public void Dispose()
    {
        _algorithm.Dispose();
    }

    internal class EncryptionCryptoTransformNone : IDisposableCryptoTransform
    {
        public int BlockSize => 1;

        public void Dispose()
        { }

        public void Transform(ReadOnlySequence<byte> data, Sequence output)
        {
            var writer = new SequenceWriter(output);
            writer.Write(data);
        }
    }
}
