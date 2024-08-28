// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;

namespace Tmds.Ssh;

public sealed class SftpFile : Stream
{
    private const long LengthNotCached = long.MaxValue;

    private readonly SftpChannel _channel;
    internal readonly byte[] Handle;
    private readonly bool _canSeek;

    private bool _disposed;

    // Tracks the position in the file for the next operation.
    // The position is updated at the start of the operation to support concurrent requests.
    private long _position;
    private long _cachedLength = LengthNotCached;

    private int _inProgress;

    internal SftpFile(SftpChannel channel, byte[] handle, FileOpenOptions options)
    {
        _channel = channel;
        Handle = handle;
        _canSeek = options.Seekable;
    }

    public override bool CanRead => true;

    public override bool CanSeek => _canSeek;

    public override bool CanWrite => true;

    public override long Length
    {
        get
        {
            ThrowIfDisposed();

            long length = _cachedLength;
            ThrowIfNotCachedLength(length);
            return length;
        }
    }

    public override long Position
    {
        get
        {
            ThrowIfDisposed();

            return _position;
        }
        set
        {
            ThrowIfDisposed();

            ArgumentOutOfRangeException.ThrowIfNegative(value);

            _position = value;
        }
    }

    public override void Flush()
    {
        ThrowIfDisposed();
    }

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        SetInProgress(true);
        try
        {
            int bytesRead = await _channel.ReadFileAsync(Handle, _position, buffer, cancellationToken).ConfigureAwait(false);
            _position += bytesRead;
            if (_position > _cachedLength)
            {
                _cachedLength = _position;
            }
            return bytesRead;
        }
        finally
        {
            SetInProgress(false);
        }
    }

    public async ValueTask<int> ReadAtAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        return await _channel.ReadFileAsync(Handle, offset, buffer, cancellationToken).ConfigureAwait(false);
    }

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public async override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        SetInProgress(true);
        try
        {
            await _channel.WriteFileAsync(Handle, _position, buffer, cancellationToken).ConfigureAwait(false);
            _position += buffer.Length;
            if (_position > _cachedLength)
            {
                _cachedLength = _position;
            }
        }
        finally
        {
            SetInProgress(false);
        }
    }

    public async ValueTask WriteAtAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        await _channel.WriteFileAsync(Handle, offset, buffer, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<FileEntryAttributes> GetAttributesAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        return await _channel.GetAttributesForHandleAsync(Handle, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask SetLengthAsync(long length, CancellationToken cancellationToken = default)
        => SetAttributesAsync(length: length, cancellationToken: cancellationToken);

    public async ValueTask<long> GetLengthAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (_cachedLength != LengthNotCached)
        {
            return _cachedLength;
        }

        FileEntryAttributes attributes = await GetAttributesAsync(cancellationToken).ConfigureAwait(false);

        return attributes.Length;
    }

    public async ValueTask SetAttributesAsync(
        UnixFilePermissions? permissions = default,
        (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
        long? length = default,
        (int Uid, int Gid)? ids = default,
        Dictionary<string, string>? extendedAttributes = default,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (length.HasValue)
        {
            SetInProgress(true);
        }
        try
        {
            await _channel.SetAttributesForHandleAsync(
                handle: Handle,
                length: length,
                ids: ids,
                permissions: permissions,
                times: times,
                extendedAttributes: extendedAttributes,
                cancellationToken).ConfigureAwait(false);

            if (length.HasValue)
            {
                if (_position > length)
                {
                    _position = length.Value;
                }
                if (_cachedLength != LengthNotCached)
                {
                    _cachedLength = length.Value;
                }
            }
        }
        finally
        {
            if (length.HasValue)
            {
                SetInProgress(false);
            }
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    public async ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        SetInProgress(true);

        _disposed = true;

        try
        {
            await _channel.CloseFileAsync(Handle, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            SetInProgress(false);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;

            _channel.CloseFile(Handle);
        }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ThrowIfDisposed();

        long cachedLength = _cachedLength;

        ThrowIfNotCachedLength(cachedLength);

        long position = origin switch
        {
            SeekOrigin.End => cachedLength + offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.Begin => offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };

        ArgumentOutOfRangeException.ThrowIfNegative(position, nameof(offset));

        _position = position;

        return position;
    }

    public override void SetLength(long value)
        => throw new NotSupportedException();

    internal void SetCachedLength(long length)
        => _cachedLength = length;

    private void SetInProgress(bool value)
    {
        if (value)
        {
            if (Interlocked.CompareExchange(ref _inProgress, 1, 0) != 0)
            {
                ThrowConcurrentOperations();
            }
        }
        else
        {
            Debug.Assert(_inProgress == 1);
            Volatile.Write(ref _inProgress, 0);
        }
    }

    private static void ThrowConcurrentOperations()
    {
        throw new InvalidOperationException("Concurrent read/write operations are not allowed.");
    }

    private static void ThrowIfNotCachedLength(long cachedLength)
    {
        if (cachedLength == LengthNotCached)
        {
            ThrowNotSupported($"Set '{nameof(FileOpenOptions.CacheLength)}' to support this operation.");
        }
    }

    private static void ThrowNotSupported(string message = "Operation not supported.")
    {
        throw new NotSupportedException(message);
    }
}
