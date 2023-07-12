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
        internal string Handle { get; }
        private bool _disposed;
        private long _offset;
        private bool _operationInProgress;

        internal SftpFile(SftpClient client, string handle)
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
                StartOperation();

                long offset = _offset;

                CompleteOperation(0);

                return offset;
            }
            set
            {
                StartOperation();

                _offset = value;

                CompleteOperation(0);
            }
        }

        public override void Flush()
        { }

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            StartOperation();

            return _client.ReadFileAsync(this, _offset, buffer);
        }

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            StartOperation();

            return _client.WriteFileAsync(this, _offset, buffer);
        }

        private void StartOperation()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
            if (_operationInProgress)
            {
                throw new InvalidOperationException();
            }
            _operationInProgress = true;
        }

        internal void CompleteOperation(int count)
        {
            _offset += count;
            _operationInProgress = false;
        }

        internal void IncreaseOffset(int count)
        {
            _offset += count;
        }

        public ValueTask CloseAsync(CancellationToken cancellationToken = default)
        {
            StartOperation();
            _disposed = true;

            return _client.CloseFileAsync(Handle);
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