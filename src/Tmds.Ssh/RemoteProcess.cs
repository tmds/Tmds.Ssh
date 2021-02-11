// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public sealed class RemoteProcess : IDisposable
    {
        private readonly SshChannel _channel;
        private StreamWriter? _stdInWriter;
        private Encoding _standardInputEncoding;
        private Encoding _standardErrorEncoding;
        private Encoding _standardOutputEncoding;

        internal RemoteProcess(SshChannel channel,
                                Encoding standardInputEncoding,
                                Encoding standardErrorEncoding,
                                Encoding standardOutputEncoding
        )
        {
            _channel = channel;
            _standardInputEncoding = standardInputEncoding;
            _standardErrorEncoding = standardErrorEncoding;
            _standardOutputEncoding = standardOutputEncoding;
        }

        public int? ExitCode => _channel.ExitCode; // TODO: non-nullable, thrown InvalidOperationException.
        public bool HasExited => _channel.ExitCode.HasValue;

        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _channel.WriteAsync(buffer, cancellationToken);

        public Stream StandardInputStream
            => StandardInputWriter.BaseStream;

        public StreamWriter StandardInputWriter
            => (_stdInWriter ??= new StreamWriter(new StdInStream(this), _standardInputEncoding) { AutoFlush = true });

        public async ValueTask<(ProcessReadType ReadType, int BytesRead)> ReadAsync(Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken cancellationToken = default)
        {
            while (true)
            {
                (ChannelReadType ReadType, int BytesRead) = await _channel.ReadAsync(stdoutBuffer, stderrBuffer, cancellationToken);
                switch (ReadType)
                {
                    case ChannelReadType.StandardOutput:
                        return (ProcessReadType.StandardOutput, BytesRead);
                    case ChannelReadType.StandardError:
                        return (ProcessReadType.StandardError, BytesRead);
                    case ChannelReadType.Closed:
                        return (ProcessReadType.ProcessExit, 0);
                    case ChannelReadType.Eof:
                        continue;
                    default:
                        throw new IndexOutOfRangeException($"Unexpected read type: {ReadType}.");
                }
            }
        }

        public void Dispose()
        {
            _channel.Dispose();
        }

        sealed class StdInStream : Stream
        {
            private readonly RemoteProcess _process;

            public StdInStream(RemoteProcess process)
            {
                _process = process;
            }

            public override bool CanRead => false;

            public override bool CanSeek => false;

            public override bool CanWrite => true;

            public override long Length => throw new NotSupportedException();

            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public override void Flush()
            { }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            public override Task FlushAsync(CancellationToken cancellationToken)
            {
                return Task.CompletedTask; // WriteAsync always flushes.
            }

            public async override ValueTask WriteAsync(System.ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
            {
                try
                {
                    await _process.WriteAsync(buffer, cancellationToken);
                }
                catch (SshException ex)
                {
                    throw new IOException($"Unable to transport data: {ex.Message}.", ex);
                }
            }
        }
    }
}
