// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.IO;

namespace Tmds.Ssh
{
    public sealed class SftpFile : Stream
    {
        private readonly SftpClient _client;
        internal byte[] Handle { get; }

        private bool _disposed;

        // Tracks the position in the file for the next operation.
        // The position is updated at the start of the operation to support concurrent requests.
        private long _position;

        internal SftpFile(SftpClient client, byte[] handle)
        {
            _client = client;
            Handle = handle;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length
        {
            get
            {
                ThrowSeekNotSupported();

                return 0;
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
                ThrowSeekNotSupported();
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

            long readOffset = Interlocked.Add(ref _position, buffer.Length) - buffer.Length;
            int bytesRead = 0;
            try
            {
                bytesRead = await _client.ReadFileAsync(Handle, readOffset, buffer, cancellationToken).ConfigureAwait(false);

                return bytesRead;
            }
            finally
            {
                Interlocked.Add(ref _position, bytesRead - buffer.Length);
            }
        }

        public async ValueTask<int> ReadAtAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            return await _client.ReadFileAsync(Handle, offset, buffer, cancellationToken).ConfigureAwait(false);
        }

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public async override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            long writeOffset = Interlocked.Add(ref _position, buffer.Length) - buffer.Length;
            try
            {
                await _client.WriteFileAsync(Handle, writeOffset, buffer, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                Interlocked.Add(ref _position, -buffer.Length);
                throw;
            }
        }

        public async ValueTask WriteAtAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            await _client.WriteFileAsync(Handle, offset, buffer, cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask<FileEntryAttributes> GetAttributesAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            return await _client.GetAttributesForHandleAsync(Handle, cancellationToken).ConfigureAwait(false);
        }

        public ValueTask SetLengthAsync(long length, CancellationToken cancellationToken = default)
            => SetAttributesAsync(length: length, cancellationToken: cancellationToken);

        public async ValueTask<long> GetLengthAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

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

            await _client.SetAttributesForHandleAsync(
                handle: Handle,
                length: length,
                ids: ids,
                permissions: permissions,
                times: times,
                extendedAttributes: extendedAttributes,
                cancellationToken).ConfigureAwait(false);

            if (_position > length)
            {
                _position = length.Value;
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
        }

        public async ValueTask CloseAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            _disposed = true;

            await _client.CloseFileAsync(Handle, cancellationToken).ConfigureAwait(false);
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

                _client.CloseFile(Handle);
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            ThrowSeekNotSupported();

            return 0;
        }

        public override void SetLength(long value)
        {
            ThrowSeekNotSupported();
        }

        private void ThrowSeekNotSupported()
            => throw new NotSupportedException("This stream does not support seek operations.");
    }
}