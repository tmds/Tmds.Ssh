// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.IO;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    class ChannelDataStream : Stream
    {
        private readonly ChannelContext _context;
        private Sequence? _receiveBuffer;
        private bool _receivedEof;

        public ChannelDataStream(ChannelContext context)
        {
            _context = context;
        }

        public override async ValueTask DisposeAsync()
        {
            await _context.DisposeAsync();

            _receiveBuffer?.Dispose();
            _receiveBuffer = null;
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

        public override System.Threading.Tasks.Task FlushAsync(System.Threading.CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public override async System.Threading.Tasks.ValueTask<int> ReadAsync(System.Memory<byte> buffer, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            if (cancellationToken.CanBeCanceled)
            {
                ThrowCancellationTokenNotSupported();
            }

            if (_receivedEof)
            {
                return 0;
            }

            int length;
            do
            {
                if (_receiveBuffer == null)
                {
                    using Packet packet = await ReceiveUntilChannelDataAsync();
                    if (packet.IsEmpty)
                    {
                        _receivedEof = true;
                        return 0;
                    }

                    _receiveBuffer = packet.MovePayload();
                    /*
                        byte      SSH_MSG_CHANNEL_DATA
                        uint32    recipient channel
                        string    data
                     */
                    // remove SSH_MSG_CHANNEL_DATA (1), recipient channel (4), and data length (4).
                    _receiveBuffer.Remove(9);
                }

                length = (int)Math.Min(buffer.Length, _receiveBuffer.Length);
                _receiveBuffer.AsReadOnlySequence().Slice(0, length).CopyTo(buffer.Span);
                _receiveBuffer.Remove(length);
                if (_receiveBuffer.IsEmpty)
                {
                    _receiveBuffer.Dispose();
                    _receiveBuffer = null;
                }
            } while (length == 0);

            return length;
        }

        private async ValueTask<Packet> ReceiveUntilChannelDataAsync()
        {
            // TODO: move this to a receive loop.
            while (true)
            {
                using var packet = await _context.ReceivePacketAsync(); // TODO SSH_MSG_CHANNEL_WINDOW_ADJUST

                switch (packet.MessageId)
                {
                    case MessageId.SSH_MSG_CHANNEL_DATA:
                        return packet.Move();
                    case MessageId.SSH_MSG_CHANNEL_EOF:
                    case MessageId.SSH_MSG_CHANNEL_CLOSE:
                        return default;
                    case MessageId.SSH_MSG_CHANNEL_REQUEST:
                        await HandleMsgChannelRequestAsync(packet);
                        break;
                    default:
                        ThrowHelper.ThrowProtocolUnexpectedMessageId(packet.MessageId!.Value);
                        break;
                }
            }
        }

        private async ValueTask HandleMsgChannelRequestAsync(Packet packet)
        {
            var channelRequest = ParseChannelRequest(packet);
            if (channelRequest.want_reply)
            {
                // If the request is not recognized or is not
                // supported for the channel, SSH_MSG_CHANNEL_FAILURE is returned.
                await _context.SendChannelFailureMessageAsync();
            }
        }

        private static (string request_type, bool want_reply) ParseChannelRequest(Packet packet)
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

        public override System.Threading.Tasks.ValueTask WriteAsync(System.ReadOnlyMemory<byte> buffer, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            if (cancellationToken.CanBeCanceled)
            {
                ThrowCancellationTokenNotSupported();
            }
            return _context.SendChannelDataAsync(buffer);
        }

        private void ThrowCancellationTokenNotSupported()
        {
            throw new NotSupportedException("A cancelable token is not supported on this operation.");
        }
    }
}