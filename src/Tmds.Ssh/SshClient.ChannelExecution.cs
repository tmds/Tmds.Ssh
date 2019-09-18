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
            private readonly Channel<Sequence> _receiveQueue;
            private readonly ChannelHandler _handler;

            public ChannelExecution(SshClient client, int channelNumber, CancellationToken abortToken, CancellationToken userToken, ChannelHandler handler)
            {
                ChannelNumber = channelNumber;
                _client = client;
                _stopChannelOrAbortCts = CancellationTokenSource.CreateLinkedTokenSource(userToken, abortToken);
                _receiveQueue = Channel.CreateUnbounded<Sequence>(new UnboundedChannelOptions
                {
                    AllowSynchronousContinuations = false, // don't block SshClient.ReceiveLoopAsync.
                    SingleWriter = true,
                    SingleReader = true
                });
                _handler = handler;
            }

            public override CancellationToken ChannelStopped => _stopChannelOrAbortCts.Token;

            public override ValueTask<Sequence> ReadPacketAsync()
                => _receiveQueue.Reader.ReadAsync(ChannelStopped);

            public override ValueTask SendPacketAsync(Sequence packet)
                => _client.SendPacketAsync(packet, ChannelStopped);

            public override Sequence RentSequence()
                => _client.RentSequence();

            internal void QueueReceivedPacket(Sequence packet)
            {
                // Unbounded queue: TryWrite is always successful.
                _receiveQueue.Writer.TryWrite(packet);
            }

            public void Dispose()
            {
                _stopChannelOrAbortCts.Dispose();
                while (_receiveQueue.Reader.TryRead(out Sequence packet))
                {
                    packet.Dispose();
                }
            }

            internal async Task ExecuteAsync()
            {
                await _handler(this);
            }
        }
    }
}
