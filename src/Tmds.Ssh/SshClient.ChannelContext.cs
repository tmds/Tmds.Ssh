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
            private readonly CancellationTokenSource _abortedTcs;
            private readonly CancellationTokenSource _stoppedCts;
            private readonly Channel<Packet> _receiveQueue;
            private bool _remoteClosedChannel;
            private LocalChannelState _localChannelState;
            private bool _disposed;
            private readonly AsyncEvent _remoteClosedChannelEvent;
            private MultiSemaphore _sendWindow;
            private int _receiveWindow;
            private AsyncEvent _channelOpenDoneEvent;
            private const int CancelByUser = 1;
            private readonly Exception AbortByConnectionClose = new Exception();
            private Exception? _abortReason = null;
            private CancellationTokenRegistration _abortOnClose;
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
                _remoteClosedChannelEvent = new AsyncEvent();
                _sendWindow = new MultiSemaphore();
                _channelOpenDoneEvent = new AsyncEvent();
                _receiveWindow = LocalWindowSize;
                _abortedTcs = new CancellationTokenSource();
                _stoppedCts = new CancellationTokenSource();

                _stopOnCancel = _abortedTcs.Token.Register(chan => ((SshClientChannelContext)chan!).Stop(StopByCancel), this);
                _abortOnClose = client.ConnectionClosed.Register(chan => ((SshClientChannelContext)chan!).Abort(AbortByConnectionClose), this);
            }

            public override void Abort(Exception reason)
            {
                if (reason == null)
                {
                    ThrowHelper.ThrowArgumentNull(nameof(reason));
                }

                // Capture the first exception to call Abort.
                // Once we cancel the token, we'll get more Abort calls.
                if (Interlocked.CompareExchange(ref _abortReason, reason, null) == null)
                {
                    _abortedTcs.Cancel();
                }
            }

            public override bool IsAborted
                => _abortReason != null;

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

            public override CancellationToken ChannelAborted => _abortedTcs.Token;

            public async override ValueTask<Packet> ReceivePacketAsync(CancellationToken ct)
            {
                if (_remoteClosedChannel)
                {
                    ThrowHelper.ThrowInvalidOperation("Peer closed the channel.");
                }

                CancellationTokenSource? cts = null;
                try
                {
                    do
                    {
                        using Packet packet = await _receiveQueue.Reader.ReadAsync(ChannelStopped, ct, ref cts).ConfigureAwait(false);

                        if (InspectReceivedPacket(packet))
                        {
                            return packet.Move();
                        }

                    } while (true);
                }
                catch (OperationCanceledException)
                {
                    ct.ThrowIfCancellationRequested();
                    ThrowIfChannelStopped();

                    throw;
                }
                finally
                {
                    cts?.Dispose();
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
                            int initialSendWindow = checked((int)reader.ReadUInt32()); // initial window size
                            RemoteMaxPacketSize = checked((int)reader.ReadUInt32()); // maximum packet size
                            _localChannelState = LocalChannelState.Opened;
                            _channelOpenDoneEvent.Set();
                            _sendWindow.Release(initialSendWindow);
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
                            _sendWindow.Release(bytesToAdd);
                        }
                        return false;
                }
                return true;
            }

            public async override ValueTask SendPacketAsync(Packet packet, CancellationToken ct)
            {
                using var pkt = packet.Move();

                MessageId? msgId = pkt.MessageId;

                if (_localChannelState != LocalChannelState.Opened &&
                    !(_localChannelState == LocalChannelState.Initial && msgId == MessageId.SSH_MSG_CHANNEL_OPEN))
                {
                    ThrowHelper.ThrowInvalidOperation("Channel closed.");
                }

                try
                {
                    await _client.SendPacketAsync(pkt.Move(), ChannelStopped, ct).ConfigureAwait(false);

                    if (msgId == MessageId.SSH_MSG_CHANNEL_OPEN)
                    {
                        _localChannelState = LocalChannelState.OpenSent;
                    }
                }
                catch (OperationCanceledException e)
                {
                    // Cancelling a send aborts the channel.
                    Abort(e);

                    ct.ThrowIfCancellationRequested();
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

            public override ValueTask CloseAsync(CancellationToken ct)
                => CloseAsync(disposing: false, ct);

            internal async ValueTask CloseAsync(bool disposing, CancellationToken ct = default)
            {
                if (!disposing && _localChannelState != LocalChannelState.Opened)
                {
                    ThrowHelper.ThrowInvalidOperation("Channel closed.");
                }

                CancellationToken contextToken = disposing ? _client.ConnectionClosed : ChannelAborted;
                try
                {
                    // Wait for the channel to be open.
                    if (_localChannelState == LocalChannelState.OpenSent)
                    {
                        await _channelOpenDoneEvent.WaitAsync(contextToken, ct).ConfigureAwait(false);
                    }

                    // Send channel close.
                    if (_localChannelState == LocalChannelState.Opened)
                    {
                        _localChannelState = LocalChannelState.Closed;

                        // We always do the send. When !disposing, we complete early.
                        ValueTask sendTask = _client.SendPacketAsync(CreateChannelCloseMessage(), contextToken, ct);
                        if (!disposing)
                        {
                            if (!sendTask.IsCompleted)
                            {
                                var tcs = new TaskCompletionSource<object?>();
                                using var setResultOnCancel =
                                    ChannelAborted.Register(s => ((TaskCompletionSource<object?>)s!).SetCanceled(), tcs);
                                Task sendTaskAsTask = sendTask.AsTask();
                                if (await Task.WhenAny(tcs.Task, sendTaskAsTask).ConfigureAwait(false) == tcs.Task)
                                {
                                    // Cancelled.
                                    await tcs.Task;
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
                        await _remoteClosedChannelEvent.WaitAsync(contextToken, ct).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException)
                {
                    ct.ThrowIfCancellationRequested();
                    ThrowIfChannelAborted();

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
                if (_disposed)
                {
                    return;
                }
                _disposed = true;

                if (_abortReason == null)
                {
                    Abort(new ObjectDisposedException(GetType().FullName));
                }

                // We don't wait for the channel close to complete
                // The SshClient calls DoDispose when that has happened.
                // If the user wants to wait, he must call 'CloseAsync'
                // explicitly.
                _client.OnChannelDisposed(this);
            }

            internal void DoDispose()
            {
                _abortOnClose.Dispose();
                _abortedTcs.Dispose();
                _stoppedCts.Dispose();
                _remoteClosedChannelEvent.Dispose();
                _sendWindow.Dispose();
                _channelOpenDoneEvent.Dispose();

                while (_receiveQueue.Reader.TryRead(out Packet packet))
                {
                    packet.Dispose();
                }
            }

            public override async ValueTask SendChannelDataAsync(ReadOnlyMemory<byte> memory, CancellationToken ct)
            {
                while (memory.Length > 0)
                {
                    try
                    {
                        int toSend = await _sendWindow.AquireAsync(aquireCount: memory.Length, exactCount: false, ChannelStopped, ct).ConfigureAwait(false);
                        await this.SendChannelDataMessageAsync(memory.Slice(0, toSend), ct).ConfigureAwait(false);
                        memory = memory.Slice(toSend);
                    }
                    catch (OperationCanceledException e)
                    {
                        // Cancelling a send aborts the channel.
                        Abort(e);

                        ct.ThrowIfCancellationRequested();
                        ThrowIfChannelStopped();

                        throw;
                    }
                }
            }

            public override void AdjustChannelWindow(int bytesToAdd)
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

                    try
                    {
                        // It's not needed to wait for this. The caller will end up waiting for new data.
                        var _ = this.SendChannelWindowAdjustMessageAsync((uint)adjust, ct: default);
                    }
                    catch
                    {
                        // Don't let *send* exceptions propagate to our caller who is *receiving* data.
                        // The exceptions will pop up elsewhere.
                    }
                }
            }

            public override void ThrowIfChannelStopped()
            {
                // If the channel is aborted later, we throw that instead
                // of the initial close. This makes it clear to our caller
                // the channel is no longer usable.
                ThrowIfChannelAborted();

                if (_stopReason == StopByPeer)
                {
                    throw new ChannelClosedException();
                }
            }

            public override void ThrowIfChannelAborted()
            {
                if (_abortReason == AbortByConnectionClose)
                {
                    _client.ThrowIfNotConnected();
                }
                else if (_abortReason != null)
                {
                    throw new ChannelAbortedException($"Channel aborted: {_abortReason.Message}", _abortReason);
                }
            }
        }
    }
}
