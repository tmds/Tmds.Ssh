// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

ref partial struct ArrayWriter
{
    private const int DefaultInitialBufferSize = 256;

    private byte[]? _buffer;
    private Span<byte> _unused;
    private int _alloced;

    public ArrayWriter()
    { }

    private Span<byte> AllocGetSpan(int minimumLength)
    {
        if (_unused.Length <= minimumLength)
        {
            EnlargeUnused(minimumLength);
        }
        return _unused;
    }

    private void EnlargeUnused(int minimumLength)
    {
        int currentLength = _buffer?.Length ?? 0;

        // Attempt to grow by the larger of the sizeHint and double the current size.
        int growBy = Math.Max(minimumLength, currentLength);

        if (currentLength == 0)
        {
            growBy = Math.Max(growBy, DefaultInitialBufferSize);
        }

        int newSize = currentLength + growBy;
        byte[] newArray = ArrayPool<byte>.Shared.Rent(newSize);
        if (_buffer is not null)
        {
            _buffer.AsSpan(0, _alloced).CopyTo(newArray);
            ArrayPool<byte>.Shared.Return(_buffer);
        }
        _buffer = newArray;
        _unused = newArray.AsSpan(_alloced);
    }

    private void AppendAlloced(int length)
    {
        _unused = _unused.Slice(length);
        _alloced += length;
    }

    public byte[] ToArray()
    {
        if (_buffer is null)
        {
            return Array.Empty<byte>();
        }

        byte[] array = _buffer.AsSpan(0, _alloced).ToArray();

        if (_buffer is not null)
        {
            ArrayPool<byte>.Shared.Return(_buffer);
            _buffer = null;
            _alloced = 0;
        }

        return array;
    }

    public void Dispose()
    {
        if (_buffer is not null)
        {
            ArrayPool<byte>.Shared.Return(_buffer);
            _buffer = null;
            _alloced = 0;
        }
    }
}
