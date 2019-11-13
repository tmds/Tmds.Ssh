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
            private readonly CancellationTokenSource _cancelledCts;
            private readonly CancellationTokenSource _stoppedCts;
            private readonly Channel<Packet> _receiveQueue;
            private bool _remoteClosedChannel;
            private LocalChannelState _localChannelState;
            private int _disposed;
            private readonly AsyncManualResetEvent _remoteClosedChannelEvent;
            private int _sendWindow;
            private AsyncManualResetEvent _sendWindowAvailableEvent;
            private int _receiveWindow;
            private AsyncManualResetEvent _channelOpenDoneEvent;
            private const int CancelByUser = 1;
            private const int CancelByConnectionClose = 2;
            private int _cancelReason = 0;
            private CancellationTokenRegistration _cancelOnClose;
            private CancellationTokenRegistration _stopOnCancel;
            private const int StopByCancel = 1;
            private const int StopByPeer = 2;
            private int _stopReason = 0;

            public SshClientChannelContext(SshClient client, uint channelNumber)
            {
                LocalChannel = channelNumber;
                _client = client;
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
                _cancelledCts = new CancellationTokenSource();
                _stoppedCts = new CancellationTokenSource();

                _stopOnCancel = _cancelledCts.Token.Register(chan => ((SshClientChannelContext)chan!).Stop(StopByCancel), this);
                _cancelOnClose = client.ConnectionClosed.Register(chan => ((SshClientChannelContext)chan!).Cancel(CancelByConnectionClose), this);
            }

            public override void Cancel()
                => Cancel(CancelByUser);

            private void Cancel(int reason)
            {
                if (reason == 0)
                {
                    ThrowHelper.ThrowArgumentOutOfRange(nameof(reason));
                }

                // Capture the first exception to call Abort.
                // Once we cancel the token, we'll get more Abort calls.
                if (Interlocked.CompareExchange(ref _cancelReason, reason, 0) == 0)
                {
                    _cancelledCts.Cancel();
                }
            }

            private void Stop(int reason)
            {
                if (reason == 0)
                {
                    ThrowHelper.ThrowArgumentOutOfRange(nameof(reason));
                }

                // Capture the first exception to call Abort.
                // Once we cancel the token, we'll get more Abort calls.
                if (Interlocked.CompareExchange(ref _stopReason, reason, 0) == 0)
                {
                    _stoppedCts.Cancel();
                }
            }

            public override CancellationToken ChannelStopped => _stoppedCts.Token;  // Peer closed channel or channel aborted.

            public override CancellationToken ChannelCancelled => _cancelledCts.Token;

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
                        using Packet packet = await _receiveQueue.Reader.ReadAsync(ChannelCancelled);

                        if (InspectReceivedPacket(packet))
                        {
                            return packet.Move();
                        }

                    } while (true);
                }
                catch (OperationCanceledException)
                {
                    ThrowIfChannelCancelled();

                    throw;
                }
            }

            private bool InspectReceivedPacket(ReadOnlyPacket packet)
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
                        Stop(StopByPeer);
                        break;
                    case MessageId.SSH_MSG_CHANNEL_CLOSE:
                        _remoteClosedChannel = true;
                        _remoteClosedChannelEvent.Set();
                        Stop(StopByPeer);
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
            {
                MessageId? msgId = packet.MessageId;

                if (_localChannelState != LocalChannelState.Opened &&
                    !(_localChannelState == LocalChannelState.Initial && msgId == MessageId.SSH_MSG_CHANNEL_OPEN))
                {
                    ThrowHelper.ThrowInvalidOperation("Channel closed.");
                }

                if (msgId == MessageId.SSH_MSG_CHANNEL_OPEN)
                {
                    _localChannelState = LocalChannelState.OpenSent;
                }

                try
                {
                    return _client.SendPacketAsync(packet, ChannelStopped);
                }
                catch (OperationCanceledException)
                {
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

                if (channelSend)
                {
                    ThrowIfChannelCancelled();
                }

                CancellationToken ct = channelSend ? ChannelCancelled : _client.ConnectionClosed;
                try
                {
                    // Wait for the channel to be open.
                    if (_localChannelState == LocalChannelState.OpenSent)
                    {
                        await _channelOpenDoneEvent.WaitAsync(ct);
                    }

                    // Send channel close.
                    if (_localChannelState == LocalChannelState.Opened)
                    {
                        _localChannelState = LocalChannelState.Closed;

                        ValueTask sendTask = _client.SendPacketAsync(CreateChannelCloseMessage());
                        if (channelSend)
                        {
                            // For a channelSend, do the send even when cancelled,
                            // but complete the task early with an exception.
                            if (!sendTask.IsCompleted)
                            {
                                var tcs = new TaskCompletionSource<object?>();
                                using var setResultOnCancel =
                                    ChannelCancelled.Register(s => ((TaskCompletionSource<object?>)s!).SetResult(null), tcs);
                                Task sendTaskAsTask = sendTask.AsTask();
                                if (await Task.WhenAny(tcs.Task, sendTaskAsTask) == tcs.Task)
                                {
                                    // Cancelled.
                                    ThrowIfChannelCancelled();
                                }
                                else
                                {
                                    await sendTaskAsTask;
                                }
                            }
                            else
                            {
                                await sendTask;
                            }
                        }
                        else
                        {
                            await sendTask;
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
                    ThrowIfChannelCancelled();

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

            public override void Dispose()
            {
                if (Interlocked.CompareExchange(ref _disposed, 1, 0) == 0)
                {
                    Cancel();

                    // We don't wait for the channel close to complete
                    // The SshClient calls DoDispose when that has happened.
                    // If the user wants to wait, he must call 'CloseAsync'
                    // explicitly.
                    _client.OnChannelDisposed(this);
                }
            }

            internal void DoDispose()
            {
                _cancelOnClose.Dispose();
                _cancelledCts.Dispose();
                _stoppedCts.Dispose();
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
                    try
                    {
                        await _sendWindowAvailableEvent.WaitAsync(ChannelStopped);
                    }
                    catch
                    {
                        ThrowIfChannelStopped();

                        throw;
                    }
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

            public override void ThrowIfChannelStopped()
            {
                if (_stopReason == StopByPeer)
                {
                    throw new ChannelClosedException();
                }
                else if (_stopReason == StopByCancel)
                {
                    ThrowIfChannelCancelled();
                }
            }

            public override void ThrowIfChannelCancelled()
            {
                if (_cancelReason == CancelByConnectionClose)
                {
                    _client.ThrowIfNotConnected();
                }
                else if (_cancelReason == CancelByUser)
                {
                    throw new OperationCanceledException();
                }
            }
        }
    }
}
