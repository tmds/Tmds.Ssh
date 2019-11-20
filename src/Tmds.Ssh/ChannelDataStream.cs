// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public class ChannelDataStream : Stream
    {
        private readonly ChannelContext _context;
        private readonly Task _receiveLoopTask;
        private readonly Channel<Packet> _readQueue;
        private Sequence? _readBuffer;
        private bool _receivedEof;
        private bool _disposed;

        public int MaxWriteLength => _context.LocalMaxPacketSize;
        public int MaxReadLength => _context.RemoteMaxPacketSize;
        public CancellationToken ChannelAborted => _context.ChannelAborted;
        public CancellationToken ChannelStopped => _context.ChannelStopped;

        internal ChannelDataStream(ChannelContext context)
        {
            _context = context;
            _readQueue = Channel.CreateUnbounded<Packet>(new UnboundedChannelOptions
            {
                AllowSynchronousContinuations = true,
                SingleWriter = true,
                SingleReader = true
            });

            _receiveLoopTask = ReceiveLoopAsync();
        }

        private async Task ReceiveLoopAsync()
        {
            try
            {
                MessageId messageId;
                do
                {
                    using var packet = await _context.ReceivePacketAsync(ct: default);
                    messageId = packet.MessageId!.Value;

                    if (messageId == MessageId.SSH_MSG_CHANNEL_REQUEST)
                    {
                        await HandleMsgChannelRequestAsync(packet);
                    }
                    else
                    {
                        _readQueue.Writer.TryWrite(packet.Move());
                    }

                } while (messageId != MessageId.SSH_MSG_CHANNEL_CLOSE);

                _readQueue.Writer.Complete();
            }
            catch (Exception e)
            {
                _readQueue.Writer.Complete(e);
            }
        }

        public void Abort(Exception reason)
            => _context.Abort(reason);

        protected override void Dispose(bool disposing)
        {
            DisposeAsync().GetAwaiter().GetResult();
        }

        public override async ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;

            // Make the ReceiveLoop stop.
            if (!_context.IsAborted)
            {
                _context.Abort(new ObjectDisposedException(GetType().FullName));
            }
            await _receiveLoopTask;
            while (_readQueue.Reader.TryRead(out Packet packet))
            {
                packet.Dispose();
            }
            _readBuffer?.Dispose();
            _readBuffer = null;

            // Close the channel.
            _context.Dispose();
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new System.NotSupportedException();

        public override long Position { get => throw new System.NotSupportedException(); set => throw new System.NotSupportedException(); }

        public override void Flush()
        { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new System.NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new System.NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new System.NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new System.NotSupportedException();
        }

        public override void Close()
        {
            throw new System.NotSupportedException();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public override async ValueTask<int> ReadAsync(System.Memory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (_receivedEof)
            {
                return 0;
            }

            int length;
            do
            {
                if (_readBuffer == null)
                {
                    using Packet packet = await ReceiveUntilChannelDataAsync(cancellationToken);
                    if (packet.IsEmpty)
                    {
                        _receivedEof = true;
                        return 0;
                    }

                    _readBuffer = packet.MovePayload();
                    /*
                        byte      SSH_MSG_CHANNEL_DATA
                        uint32    recipient channel
                        string    data
                     */
                    // remove SSH_MSG_CHANNEL_DATA (1), recipient channel (4), and data length (4).
                    _readBuffer.Remove(9);
                }

                length = (int)Math.Min(buffer.Length, _readBuffer.Length);
                _readBuffer.AsReadOnlySequence().Slice(0, length).CopyTo(buffer.Span);
                _readBuffer.Remove(length);
                if (_readBuffer.IsEmpty)
                {
                    _readBuffer.Dispose();
                    _readBuffer = null;
                }
            } while (length == 0);

            _context.AdjustChannelWindow(length);

            return length;
        }

        private async ValueTask<Packet> ReceiveUntilChannelDataAsync(CancellationToken ct)
        {
            CancellationTokenSource? cts = null;
            try
            {
                while (true)
                {
                    using var packet = await _readQueue.Reader.ReadAsync(_context.ChannelAborted, ct, ref cts);

                    switch (packet.MessageId)
                    {
                        case MessageId.SSH_MSG_CHANNEL_DATA:
                            return packet.Move();
                        case MessageId.SSH_MSG_CHANNEL_EOF:
                        case MessageId.SSH_MSG_CHANNEL_CLOSE:
                            return default;
                        default:
                            ThrowHelper.ThrowProtocolUnexpectedMessageId(packet.MessageId!.Value);
                            break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                ct.ThrowIfCancellationRequested();
                _context.ThrowIfChannelAborted();

                throw;
            }
            finally
            {
                cts?.Dispose();
            }
        }

        private async ValueTask HandleMsgChannelRequestAsync(ReadOnlyPacket packet)
        {
            var channelRequest = ParseChannelRequest(packet);
            if (channelRequest.want_reply)
            {
                // If the request is not recognized or is not
                // supported for the channel, SSH_MSG_CHANNEL_FAILURE is returned.
                await _context.SendChannelFailureMessageAsync(ct: default);
            }
        }

        private static (string request_type, bool want_reply) ParseChannelRequest(ReadOnlyPacket packet)
        {
            /*
                byte      SSH_MSG_CHANNEL_REQUEST
                uint32    recipient channel
                string    request type in US-ASCII characters only
                boolean   want reply
                ....      type-specific data follows
             */
            var reader = packet.GetReader();
            reader.ReadMessageId(MessageId.SSH_MSG_CHANNEL_REQUEST);
            reader.SkipUInt32();
            string request_type = reader.ReadUtf8String();
            bool want_reply = reader.ReadBoolean();
            return (request_type, want_reply);
        }

        public override ValueTask WriteAsync(System.ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
        {
            return _context.SendChannelDataAsync(buffer, cancellationToken);
        }

        private void ThrowCancellationTokenNotSupported()
        {
            throw new NotSupportedException("A cancelable token is not supported on this operation.");
        }
    }
}