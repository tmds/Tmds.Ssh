// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public sealed partial class SshClient
    {
        class ChannelExecution : ChannelContext, IDisposable
        {
            private readonly SshClient _client;
            private readonly CancellationTokenSource _stopChannelOrAbortCts;
            private readonly Channel<Packet> _receiveQueue;
            private readonly ChannelHandler _handler;

            public ChannelExecution(SshClient client, int channelNumber, CancellationToken abortToken, CancellationToken userToken, ChannelHandler handler)
            {
                ChannelNumber = channelNumber;
                _client = client;
                _stopChannelOrAbortCts = CancellationTokenSource.CreateLinkedTokenSource(userToken, abortToken);
                _receiveQueue = Channel.CreateUnbounded<Packet>(new UnboundedChannelOptions
                {
                    AllowSynchronousContinuations = false, // don't block SshClient.ReceiveLoopAsync.
                    SingleWriter = true,
                    SingleReader = true
                });
                _handler = handler;
            }

            public override CancellationToken ChannelStopped => _stopChannelOrAbortCts.Token;

            public override ValueTask<Packet> ReadPacketAsync()
                => _receiveQueue.Reader.ReadAsync(ChannelStopped);

            public override ValueTask SendPacketAsync(Packet packet)
                => _client.SendPacketAsync(packet, ChannelStopped);

            public override Packet RentPacket()
                => _client.RentPacket();

            internal void QueueReceivedPacket(Packet packet)
            {
                // Unbounded queue: TryWrite is always successful.
                _receiveQueue.Writer.TryWrite(packet);
            }

            public void Dispose()
            {
                _stopChannelOrAbortCts.Dispose();
                while (_receiveQueue.Reader.TryRead(out Packet packet))
                {
                    packet.Dispose();
                }
            }

            internal async Task ExecuteAsync()
            {
                await _handler(this);
                // TODO: this musn't complete until the peer has sent us a channel close
                //       or the connection was closed.
            }
        }
    }
}
