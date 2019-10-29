// This file is part of Tmds.Ssh which is released under MIT.
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
            private readonly AsyncManualResetEvent _remoteClosedChannelEvent;
            private int _sendWindow;
            private AsyncManualResetEvent _sendWindowAvailableEvent;
            private int _receiveWindow;

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
                // ManualResetEventSlim doesn't support async wait, so use a SemaphoreSlim.
                _remoteClosedChannelEvent = new AsyncManualResetEvent();
                _sendWindowAvailableEvent = new AsyncManualResetEvent();
                _receiveWindow = LocalWindowSize;
            }

            public override void Cancel()
            {
                _stopChannelOrAbortCts.Cancel();
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

                do
                {
                    using Packet packet = await _receiveQueue.Reader.ReadAsync(cancellationToken);

                    if (InspectReceivedPacket(packet))
                    {
                        return packet.Move();
                    }

                } while (true);
            }

            private bool InspectReceivedPacket(Packet packet)
            {
                switch (packet.MessageId)
                {
                    case MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                        {
                            /*
                                byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
                                uint32    recipient channel
                                uint32    sender channel
                                uint32    initial window size
                                uint32    maximum packet size
                                ....      channel type specific data follows
                             */
                            var reader = packet.GetReader();
                            reader.ReadByte();   // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
                            reader.SkipUInt32(); // recipient channel
                            RemoteChannel = reader.ReadUInt32(); // sender channel
                            _sendWindow = checked((int)reader.ReadUInt32()); // initial window size
                            RemoteMaxPacketSize = checked((int)reader.ReadUInt32()); // maximum packet size
                            if (_sendWindow != 0)
                            {
                                _sendWindowAvailableEvent.Set();
                            }
                        }
                        break;
                    case MessageId.SSH_MSG_CHANNEL_CLOSE:
                        _remoteClosedChannel = true;
                        _remoteClosedChannelEvent.Set();
                        break;
                    case MessageId.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                        {
                            /*
                                byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
                                uint32    recipient channel
                                uint32    bytes to add
                             */
                            var reader = packet.GetReader();
                            reader.ReadByte();   // SSH_MSG_CHANNEL_WINDOW_ADJUST
                            reader.SkipUInt32(); // recipient channel
                            int bytesToAdd = checked((int)reader.ReadUInt32()); // bytes to add
                            reader.ReadEnd();
                            int newSize = Interlocked.Add(ref _sendWindow, bytesToAdd);
                            if (newSize < 0)
                            {
                                ThrowHelper.ThrowArgumentOutOfRange(nameof(bytesToAdd));
                            }
                            if (newSize == bytesToAdd) // _sendWindow was zero.
                            {
                                _sendWindowAvailableEvent.Set();
                            }
                        }
                        return false;
                }
                return true;
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

            public override ValueTask CloseAsync()
                => CloseAsync(ChannelStopped);

            internal async ValueTask CloseAsync(CancellationToken ct)
            {
                // Send channel close.
                if (!_localClosedChannel)
                {
                    using var closeMessage = CreateChannelCloseMessage();
                    await SendPacketAsync(closeMessage, ct);
                }

                // Wait for close received.
                await _remoteClosedChannelEvent.WaitAsync(ct);

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

            public override ValueTask DisposeAsync()
            {
                if (Interlocked.CompareExchange(ref _disposed, 1, 0) == 0)
                {
                    // We don't wait for the channel close to complete
                    // The SshClient calls DoDispose when that has happened.
                    // If the user wants to wait, he must call 'CloseAsync'
                    // explicitly.
                    _client.OnChannelDisposed(this);
                }

                return new ValueTask(Task.CompletedTask);
            }

            internal void DoDispose()
            {
                _stopChannelOrAbortCts.Dispose();
                _remoteClosedChannelEvent.Dispose();
                _sendWindowAvailableEvent.Dispose();

                while (_receiveQueue.Reader.TryRead(out Packet packet))
                {
                    packet.Dispose();
                }
            }

            public override async ValueTask SendChannelDataAsync(ReadOnlyMemory<byte> memory)
            {
                while (memory.Length > 0)
                {
                    int sendWindow = Volatile.Read(ref _sendWindow);
                    if (sendWindow > 0)
                    {
                        int toSend = Math.Min(sendWindow, memory.Length);
                        toSend = Math.Min(toSend, RemoteMaxPacketSize);
                        if (Interlocked.CompareExchange(ref _sendWindow, sendWindow - toSend, sendWindow) == sendWindow)
                        {
                            await SendPacketAsync(CreateChannelDataMessage(this, memory.Slice(0, toSend)));
                            memory = memory.Slice(toSend);
                            if (memory.IsEmpty)
                            {
                                return;
                            }
                        }
                    }
                    await _sendWindowAvailableEvent.WaitAsync(ChannelStopped);
                }

                static Packet CreateChannelDataMessage(ChannelContext context, ReadOnlyMemory<byte> memory)
                {
                    /*
                        byte      SSH_MSG_CHANNEL_DATA
                        uint32    recipient channel
                        string    data
                    */

                    using var packet = context.RentPacket();
                    var writer = packet.GetWriter();
                    writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_DATA);
                    writer.WriteUInt32(context.RemoteChannel);
                    writer.WriteString(memory.Span);
                    return packet.Move();
                }
            }

            public async override ValueTask AdjustChannelWindowAsync(int bytesToAdd)
            {
                if (bytesToAdd <= 0)
                {
                    ThrowHelper.ThrowArgumentOutOfRange(nameof(bytesToAdd));
                }
                int newWindow = Interlocked.Add(ref _receiveWindow, -bytesToAdd);
                if (newWindow < 0)
                {
                    ThrowHelper.ThrowProtocolDataWindowExceeded();
                }

                // Send window adjust when we drop below half the window size.
                int halfWindowSize = LocalWindowSize / 2;
                if (newWindow < halfWindowSize &&
                    ((newWindow + bytesToAdd) >= halfWindowSize))
                {
                    int adjust = LocalWindowSize - newWindow;
                    using var packet = CreateChannelWindowAdjustMessage(this, (uint)adjust);
                    Interlocked.Add(ref _receiveWindow, (int)adjust);
                    await SendPacketAsync(packet);
                }

                static Packet CreateChannelWindowAdjustMessage(ChannelContext context, uint bytesToAdd)
                {
                    /*
                        byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
                        uint32    recipient channel
                        uint32    bytes to add
                    */
                    using var packet = context.RentPacket();
                    var writer = packet.GetWriter();
                    writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_WINDOW_ADJUST);
                    writer.WriteUInt32(context.RemoteChannel);
                    writer.WriteUInt32(bytesToAdd);
                    return packet.Move();
                }
            }
        }
    }
}
