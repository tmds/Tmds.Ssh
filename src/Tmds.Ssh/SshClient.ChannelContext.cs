// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
        public sealed partial class SshClient
        {
            class SshClientChannelContext : ChannelContext
            {
                private readonly SshClient _client;
                private readonly CancellationTokenSource _stopChannelOrAbortCts;
                private readonly Channel<Packet> _receiveQueue;
                private bool _remoteClosedChannel;
                private bool _localClosedChannel;
                private int _disposed;

                public SshClientChannelContext(SshClient client, uint channelNumber, CancellationToken userToken)
                {
                    LocalChannel = channelNumber;
                    _client = client;
                    _stopChannelOrAbortCts = CancellationTokenSource.CreateLinkedTokenSource(userToken, client.ConnectionClosed);
                    _receiveQueue = Channel.CreateUnbounded<Packet>(new UnboundedChannelOptions
                    {
                        AllowSynchronousContinuations = false, // don't block SshClient.ReceiveLoopAsync.
                        SingleWriter = true,
                        SingleReader = true
                    });
                }

                public override CancellationToken ChannelStopped => _stopChannelOrAbortCts.Token;

                public override ValueTask<Packet> ReceivePacketAsync()
                    => ReceivePacketAsync(ChannelStopped);

                private async ValueTask<Packet> ReceivePacketAsync(CancellationToken cancellationToken)
                {
                    if (_remoteClosedChannel)
                    {
                        ThrowHelper.ThrowInvalidOperation("Peer closed the channel.");
                    }

                    Packet packet = default;
                    try
                    {
                        // In case the token is cancelled, we dequeue any pending packets,
                        // before starting to throw OperationCanceledException.
                        bool cancellationRequested = cancellationToken.IsCancellationRequested;
                        if (!cancellationRequested)
                        {
                            try
                            {
                                packet = await _receiveQueue.Reader.ReadAsync(cancellationToken);
                            }
                            catch (OperationCanceledException)
                            {
                                cancellationRequested = true;
                            }
                        }

                        if (cancellationRequested)
                        {
                            if (!_receiveQueue.Reader.TryRead(out packet))
                            {
                                Debug.Assert(cancellationToken.IsCancellationRequested);
                                cancellationToken.ThrowIfCancellationRequested();
                            }
                        }

                        InspectReceivedPacket(packet);

                        return packet.Move();
                    }
                    finally
                    {
                        packet.Dispose();
                    }
                }

                private void InspectReceivedPacket(Packet packet)
                {
                    switch (packet.MessageId)
                    {
                        case MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                            var reader = packet.GetReader();
                            reader.ReadUInt32(); // recipient channel
                            RemoteChannel = reader.ReadUInt32();
                            RemoteWindowSize = reader.ReadUInt32();
                            RemoteMaxPacketSize = reader.ReadUInt32();
                            break;
                        case MessageId.SSH_MSG_CHANNEL_CLOSE:
                            _remoteClosedChannel = true;

                            // We cancel everything that is on-going for the channel
                            // which should cause the user to call `DisposeAsync`
                            // which causes us to send back a SSH_MSG_CHANNEL_CLOSE.
                            // In case this doesn't work well for certain types of channels,
                            // we can leave this out and leave it to the channel implementation.
                            _stopChannelOrAbortCts.Cancel();
                            break;
                    }
                }

                public override ValueTask SendPacketAsync(Packet packet)
                    => SendPacketAsync(packet, ChannelStopped);

                private ValueTask SendPacketAsync(Packet packet, CancellationToken ct)
                {
                    if (_localClosedChannel)
                    {
                        ThrowHelper.ThrowInvalidOperation("Channel closed");
                    }

                    InspectSentPacket(packet);
                    return _client.SendPacketAsync(packet, ct);
                }


                private void InspectSentPacket(Packet packet)
                {
                    switch (packet.MessageId)
                    {
                        case MessageId.SSH_MSG_CHANNEL_CLOSE:
                            _localClosedChannel = true;
                            break;
                    }
                }

                public override Packet RentPacket()
                    => _client.RentPacket();

                internal void QueueReceivedPacket(Packet packet)
                {
                    // Unbounded queue: TryWrite is always successful.
                    _receiveQueue.Writer.TryWrite(packet);
                }

                public async override ValueTask DisposeAsync()
                {
                    if (Interlocked.CompareExchange(ref _disposed, 1, 0) == 1)
                    {
                        return;
                    }

                    // TODO: get rid of these potentially 'blocking' operations in DisposeAsync.

                    // Send channel close.
                    if (!_localClosedChannel)
                    {
                        try
                        {
                            using var closeMessage = CreateChannelCloseMessage();
                            await SendPacketAsync(closeMessage, _client.ConnectionClosed);
                        }
                        catch
                        { }
                    }

                    // Receive channel close.
                    try
                    {
                        while (!_remoteClosedChannel)
                        {
                            using var packet = await ReceivePacketAsync(_client.ConnectionClosed);
                            _remoteClosedChannel = packet.MessageId == MessageId.SSH_MSG_CHANNEL_CLOSE;
                        }
                    }
                    catch
                    { }

                    // Past this, the client will no longer queue packets for this channel.
                    _client.OnChannelClosed(this);

                    _stopChannelOrAbortCts.Dispose();

                    while (_receiveQueue.Reader.TryRead(out Packet packet))
                    {
                        packet.Dispose();
                    }

                    Packet CreateChannelCloseMessage()
                    {
                        /*
                            byte      SSH_MSG_CHANNEL_CLOSE
                            uint32    recipient channel
                        */
                        using var packet = RentPacket();
                        var writer = packet.GetWriter();
                        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_CLOSE);
                        writer.WriteUInt32(RemoteChannel);
                        return packet.Move();
                    }
                }
            }
        }
    }
