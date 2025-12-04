// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;

namespace Tmds.Ssh;

/// <summary>
/// <see cref="Stream"/> for reading and writing SFTP files.
/// </summary>
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

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => _canSeek;

    /// <inheritdoc />
    public override bool CanWrite => true;

    /// <inheritdoc />
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

    /// <inheritdoc />
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

    /// <inheritdoc />
    public override void Flush()
    {
        ThrowIfDisposed();
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

    /// <inheritdoc />
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc />
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

    /// <summary>
    /// Reads data from the file at a specific offset without changing Position.
    /// </summary>
    /// <param name="buffer">Buffer to read into.</param>
    /// <param name="offset">File offset to read from.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>Number of bytes read.</returns>
    public async ValueTask<int> ReadAtAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        return await _channel.ReadFileAsync(Handle, offset, buffer, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

    /// <inheritdoc />
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc />
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

    /// <summary>
    /// Writes data to the file at a specific offset without changing position.
    /// </summary>
    /// <param name="buffer">Buffer containing data to write.</param>
    /// <param name="offset">File offset to write at.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public async ValueTask WriteAtAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        await _channel.WriteFileAsync(Handle, offset, buffer, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets file attributes.
    /// </summary>
    /// <remarks>
    /// To retrieve extended attributes, use the overload that accepts a <c>filter</c> argument.
    /// </remarks>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The <see cref="FileEntryAttributes"/>.</returns>
    public ValueTask<FileEntryAttributes> GetAttributesAsync(CancellationToken cancellationToken = default)
        => GetAttributesAsync([], cancellationToken);

    /// <summary>
    /// Gets file attributes.
    /// </summary>
    /// <param name="filter">Extended attributes to include. Set to <see langword="null"/> to include all.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The <see cref="FileEntryAttributes"/>.</returns>
    public async ValueTask<FileEntryAttributes> GetAttributesAsync(string[]? filter, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        return await _channel.GetAttributesForHandleAsync(Handle, filter, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sets the file length.
    /// </summary>
    /// <param name="length">The new file length.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public ValueTask SetLengthAsync(long length, CancellationToken cancellationToken = default)
        => SetAttributesAsync(length: length, cancellationToken: cancellationToken);

    /// <summary>
    /// Gets the file length.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The file length.</returns>
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

    /// <summary>
    /// Sets file attributes.
    /// </summary>
    /// <param name="permissions"><see cref="UnixFilePermissions"/> to set.</param>
    /// <param name="times">Access and modification times to set.</param>
    /// <param name="length">File length to set (truncates or extends).</param>
    /// <param name="ids">User and group IDs to set.</param>
    /// <param name="extendedAttributes">Extended attributes to set.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public async ValueTask SetAttributesAsync(
        UnixFilePermissions? permissions = default,
        (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
        long? length = default,
        (int Uid, int Gid)? ids = default,
        IEnumerable<KeyValuePair<string, Memory<byte>>>? extendedAttributes = default,
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

    /// <summary>
    /// Closes the file.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
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

    /// <inheritdoc />
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

    /// <inheritdoc />
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

    /// <inheritdoc />
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
