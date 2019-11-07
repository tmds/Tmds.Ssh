// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public sealed partial class SshClient
    {
        class SshClientChannelContext : ChannelContext
        {
            enum LocalChannelState
            {
                Initial,
                OpenSent,
                Opened,
                Closed
            }

            private readonly SshClient _client;
            private readonly CancellationTokenSource _channelOrConnectionAborted;
            private readonly Channel<Packet> _receiveQueue;
            private bool _remoteClosedChannel;
            private LocalChannelState _localChannelState;
            private int _disposed;
            private readonly AsyncManualResetEvent _remoteClosedChannelEvent;
            private int _sendWindow;
            private AsyncManualResetEvent _sendWindowAvailableEvent;
            private int _receiveWindow;
            private AsyncManualResetEvent _channelOpenDoneEvent;

            public SshClientChannelContext(SshClient client, uint channelNumber)
            {
                LocalChannel = channelNumber;
                _client = client;
                _channelOrConnectionAborted = CancellationTokenSource.CreateLinkedTokenSource(client.ConnectionClosed);
                _receiveQueue = Channel.CreateUnbounded<Packet>(new UnboundedChannelOptions
                {
                    AllowSynchronousContinuations = false, // don't block SshClient.ReceiveLoopAsync.
                    SingleWriter = true,
                    SingleReader = true
                });
                // ManualResetEventSlim doesn't support async wait, so use a SemaphoreSlim.
                _remoteClosedChannelEvent = new AsyncManualResetEvent();
                _sendWindowAvailableEvent = new AsyncManualResetEvent();
                _channelOpenDoneEvent = new AsyncManualResetEvent();
                _receiveWindow = LocalWindowSize;
            }

            public override void Abort()
            {
                _channelOrConnectionAborted.Cancel();
            }

            public override CancellationToken ChannelStopped => _channelOrConnectionAborted.Token;

            public async override ValueTask<Packet> ReceivePacketAsync()
            {
                if (_remoteClosedChannel)
                {
                    ThrowHelper.ThrowInvalidOperation("Peer closed the channel.");
                }

                try
                {
                    do
                    {
                        using Packet packet = await _receiveQueue.Reader.ReadAsync(ChannelStopped);

                        if (InspectReceivedPacket(packet))
                        {
                            return packet.Move();
                        }

                    } while (true);
                }
                catch (OperationCanceledException)
                {
                    ThrowIfChannelStopped();

                    throw;
                }
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
                            _localChannelState = LocalChannelState.Opened;
                            _channelOpenDoneEvent.Set();
                            if (_sendWindow != 0)
                            {
                                _sendWindowAvailableEvent.Set();
                            }
                        }
                        break;
                    case MessageId.SSH_MSG_CHANNEL_OPEN_FAILURE:
                        _localChannelState = LocalChannelState.Closed;
                        _remoteClosedChannel = true;
                        _remoteClosedChannelEvent.Set();
                        _channelOpenDoneEvent.Set();
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

            public async override ValueTask SendPacketAsync(Packet packet)
            {
                MessageId? msgId = packet.MessageId;

                if (_localChannelState != LocalChannelState.Opened &&
                    !(_localChannelState == LocalChannelState.Initial && msgId == MessageId.SSH_MSG_CHANNEL_OPEN))
                {
                    ThrowHelper.ThrowInvalidOperation("Channel closed.");
                }

                ThrowIfChannelStopped();

                switch (msgId)
                {
                    case MessageId.SSH_MSG_CHANNEL_OPEN:
                        _localChannelState = LocalChannelState.OpenSent;
                        break;
                    case MessageId.SSH_MSG_CHANNEL_CLOSE:
                        _localChannelState = LocalChannelState.Closed;
                        break;
                }

                try
                {
                    await _client.SendPacketAsync(packet, ChannelStopped);
                }
                catch
                {
                    Abort();

                    ThrowIfChannelStopped();

                    throw;
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
                => CloseAsync(channelSend: true);

            internal async ValueTask CloseAsync(bool channelSend)
            {
                if (channelSend && _localChannelState != LocalChannelState.Opened)
                {
                    ThrowHelper.ThrowInvalidOperation("Channel closed.");
                }

                CancellationToken ct = channelSend ? ChannelStopped : _client.ConnectionClosed;
                try
                {
                    // Send channel close.
                    if (_localChannelState == LocalChannelState.OpenSent)
                    {
                        await _channelOpenDoneEvent.WaitAsync(ct);
                    }

                    if (_localChannelState == LocalChannelState.Opened)
                    {
                        using var closeMessage = CreateChannelCloseMessage();
                        if (channelSend)
                        {
                            await SendPacketAsync(closeMessage);
                        }
                        else
                        {
                            _localChannelState = LocalChannelState.Closed;
                            // by-pass ChannelStopped.
                            await _client.SendPacketAsync(closeMessage);
                        }
                    }

                    if (_localChannelState != LocalChannelState.Initial)
                    {
                        // Wait for peer close.
                        await _remoteClosedChannelEvent.WaitAsync(ct);
                    }
                }
                catch (OperationCanceledException)
                {
                    ThrowIfChannelStopped();

                    throw;
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

                return default; // Completed ValueTask.
            }

            internal void DoDispose()
            {
                _channelOrConnectionAborted.Dispose();
                _remoteClosedChannelEvent.Dispose();
                _sendWindowAvailableEvent.Dispose();
                _channelOpenDoneEvent.Dispose();

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
                            await this.SendChannelDataMessageAsync(memory.Slice(0, toSend));
                            memory = memory.Slice(toSend);
                            if (memory.IsEmpty)
                            {
                                return;
                            }
                        }
                    }
                    await _sendWindowAvailableEvent.WaitAsync(ChannelStopped);
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
                    Interlocked.Add(ref _receiveWindow, adjust);
                    await this.SendChannelWindowAdjustMessageAsync((uint)adjust);
                }
            }

            private void ThrowNewChannelAbortedException()
            {
                throw new ChannelAbortedException();
            }

            public override void ThrowIfChannelStopped()
            {
                if (ChannelStopped.IsCancellationRequested)
                {
                    _client.ThrowIfNotConnected();

                    ThrowNewChannelAbortedException();
                }
            }
        }
    }
}
