// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
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

        public override bool CanRead => throw new NotImplementedException();

        public override bool CanSeek => throw new NotImplementedException();

        public override bool CanWrite => throw new NotImplementedException();

        public override long Length => throw new NotImplementedException();

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

            long readOffset = Interlocked.Add(ref _position, buffer.Length) - buffer.Length;
            int bytesRead = 0;
            try
            {
                bytesRead = await _client.ReadFileAsync(Handle, readOffset, buffer, cancellationToken);

                return bytesRead;
            }
            finally
            {
                Interlocked.Add(ref _position, bytesRead - buffer.Length);
            }
        }

        public ValueTask<int> ReadAtAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            return _client.ReadFileAsync(Handle, offset, buffer, cancellationToken);
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
                await _client.WriteFileAsync(Handle, writeOffset, buffer, cancellationToken);
            }
            catch
            {
                Interlocked.Add(ref _position, -buffer.Length);
                throw;
            }
        }

        public ValueTask WriteAtAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            return _client.WriteFileAsync(Handle, offset, buffer, cancellationToken);
        }

        public ValueTask<FileEntryAttributes> GetAttributesAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            return _client.GetAttributesForHandleAsync(Handle, cancellationToken);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
        }

        public ValueTask CloseAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            _disposed = true;

            return _client.CloseFileAsync(Handle, cancellationToken);
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
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }
    }
}