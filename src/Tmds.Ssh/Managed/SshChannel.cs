// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Tmds.Ssh.Managed;

sealed partial class SshChannel : ISshChannel
{
    enum AbortState
    {
        NotAborted,

        Closed, // Channel closed by peer
        ConnectionClosed, // Connection closed
        Canceled, // Canceled by user
        Aborted, // Channel closed due to an error

        Disposed // By user
    }

    public SshChannel(ManagedSshClient client, SequencePool sequencePool, uint channelNumber, Type channelType)
    {
        LocalChannel = channelNumber;
        _client = client;
        _sequencePool = sequencePool;
        _receiveWindow = MaxWindowSize;
        _channelType = channelType;
    }

    public CancellationToken ChannelAborted
    {
        get
        {
            ThrowIfDisposed();

            return _abortedTcs.Token;
        }
    }
    public int? ExitCode { get; private set; }
    public int SendMaxPacket { get; private set; }
    public int ReceiveMaxPacket => Constants.MaxDataPacketSize;
    private int MaxWindowSize => Constants.DefaultWindowSize;

    internal uint LocalChannel { get; set; }
    private uint RemoteChannel { get; set; }

    private readonly ManagedSshClient _client;
    private readonly SequencePool _sequencePool;
    private readonly Type _channelType;
    private readonly CancellationTokenSource _abortedTcs = new();
    private readonly Channel<Packet> _receiveQueue = Channel.CreateUnbounded<Packet>(new UnboundedChannelOptions
    {
        AllowSynchronousContinuations = false, // don't block ManagedSshClient.ReceiveLoopAsync.
        SingleWriter = false, // Assume completing concurrently also means different writers.
        SingleReader = false  // We only expect a single caller of ReceivePacketAsync, but Dispose may also read from the queue.
    });
    private SemaphoreSlim _sendWindowAvailableEvent = new SemaphoreSlim(initialCount: 0);
    private int _abortState = (int)AbortState.NotAborted;
    private bool _skippingStdout;
    private bool _skippingStderr;
    private Sequence? _stdoutData;
    private Sequence? _stderrData;
    private int _receiveWindow;
    private int _sendCloseOnDispose;
    private int _disposed;
    private int _sendWindow;
    private Exception? _abortReason = null;
    private object _gate => _receiveQueue;

    public async ValueTask<(ChannelReadType ReadType, int BytesRead)> ReadAsync
        (Memory<byte>? stdoutBuffer = default,
        Memory<byte>? stderrBuffer = default,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (stdoutBuffer is { Length: 0 })
        {
            throw new ArgumentException("Buffer length cannot be zero.", nameof(stdoutBuffer));
        }
        if (stderrBuffer is { Length: 0 })
        {
            throw new ArgumentException("Buffer length cannot be zero.", nameof(stderrBuffer));
        }
        if (stdoutBuffer.HasValue && _skippingStdout)
        {
            throw new InvalidOperationException("Standard output is being skipped.");
        }
        if (stderrBuffer.HasValue && _skippingStderr)
        {
            throw new InvalidOperationException("Standard error is being skipped.");
        }
        _skippingStdout = !stdoutBuffer.HasValue;
        _skippingStderr = !stderrBuffer.HasValue;

        do
        {
            if (_stdoutData != null)
            {
                int length = MoveDataFromSequenceToMemory(ref _stdoutData, stdoutBuffer);
                if (length != 0)
                {
                    return (ChannelReadType.StandardOutput, length);
                }
            }

            if (_stderrData != null)
            {
                int length = MoveDataFromSequenceToMemory(ref _stderrData, stderrBuffer);
                if (length != 0)
                {
                    return (ChannelReadType.StandardError, length);
                }
            }

            using Packet packet = await ReceivePacketAsync(cancellationToken);
            MessageId messageId = packet.MessageId!.Value;
            switch (messageId)
            {
                case MessageId.SSH_MSG_CHANNEL_EOF:
                    return (ChannelReadType.Eof, 0);
                case MessageId.SSH_MSG_CHANNEL_CLOSE:
                    return (ChannelReadType.Closed, 0);
                case MessageId.SSH_MSG_CHANNEL_DATA:
                    _stdoutData = packet.MovePayload();
                    // remove SSH_MSG_CHANNEL_DATA (1), recipient channel (4), and data length (4).
                    _stdoutData.Remove(9);
                    break;
                case MessageId.SSH_MSG_CHANNEL_EXTENDED_DATA:
                    const int SSH_EXTENDED_DATA_STDERR = 1;
                    /*
                        byte      SSH_MSG_CHANNEL_EXTENDED_DATA
                        uint32    recipient channel
                        uint32    data_type_code
                        string    data
                    */
                    uint data_type_code = ReadDataType(packet);
                    if (data_type_code == SSH_EXTENDED_DATA_STDERR)
                    {
                        _stderrData = packet.MovePayload();
                        // remove SSH_MSG_CHANNEL_EXTENDED_DATA (1), recipient channel (4), data_type_code (4), and data length (4).
                        _stderrData.Remove(13);
                    }
                    else
                    {
                        throw new NotSupportedException($"Unexpected data type: {data_type_code}");
                    }
                    break;
                default:
                    throw new InvalidOperationException($"Unexpected {messageId}.");
            }
        } while (true);

        static uint ReadDataType(ReadOnlyPacket extendedDataPayload)
        {
            /*
                byte      SSH_MSG_CHANNEL_EXTENDED_DATA
                uint32    recipient channel
                uint32    data_type_code
                string    data
            */
            var reader = extendedDataPayload.GetReader();
            // skip SSH_MSG_CHANNEL_EXTENDED_DATA, recipient channel
            reader.Skip(5);
            uint data_type_code = reader.ReadUInt32();
            return data_type_code;
        }
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> memory, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        while (memory.Length > 0)
        {
            if (_abortState >= (int)AbortState.Closed)
            {
                throw CreateCloseException();
            }

            int sendWindow = Volatile.Read(ref _sendWindow);
            if (sendWindow > 0)
            {
                int toSend = Math.Min(sendWindow, memory.Length);
                toSend = Math.Min(toSend, SendMaxPacket);
                if (Interlocked.CompareExchange(ref _sendWindow, sendWindow - toSend, sendWindow) == sendWindow)
                {
                    TrySendChannelDataMessage(memory.Slice(0, toSend));
                    memory = memory.Slice(toSend);
                    if (memory.IsEmpty)
                    {
                        return;
                    }
                }
            }
            else
            {
                try
                {
                    await _sendWindowAvailableEvent.WaitAsync(cancellationToken).ConfigureAwait(false);
                    await Task.Yield(); // Get of the receive loop.
                }
                catch (OperationCanceledException)
                {
                    Cancel();

                    cancellationToken.ThrowIfCancellationRequested();
                    throw CreateCloseException();
                }
            }
        }
    }

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) == 1)
        {
            return;
        }
        Abort(AbortState.Disposed);

        while (_receiveQueue.Reader.TryRead(out Packet packet))
        {
            packet.Dispose();
        }

        TrySendCloseOnDispose();

        // Don't dispose _abortedTcs/_sendWindowAvailableEvent as Abort may still call
        // on them if the peer had not yet closed the channel.
    }

    public void Abort(Exception exception)
        => Abort(AbortState.Aborted, exception);

    public Exception CreateCloseException()
        => (AbortState)_abortState switch
        {
            AbortState.ConnectionClosed => _client.CreateCloseException(),
            AbortState.Canceled => new SshChannelClosedException(SshChannelClosedException.ChannelClosedByCancel),
            AbortState.Aborted => new SshChannelClosedException(SshChannelClosedException.ChannelClosedByAbort, _abortReason),
            AbortState.Closed => new SshChannelClosedException(SshChannelClosedException.ChannelClosedByPeer),
            AbortState.Disposed => new SshChannelClosedException(SshChannelClosedException.ChannelClosedByDispose),
            _ => throw new IndexOutOfRangeException($"Unhandled state: {_abortState}."),
        };

    private void Cancel()
        => Abort(AbortState.Canceled);

    private void Abort(AbortState state, Exception? abortException = null)
    {
        Debug.Assert(state >= AbortState.Closed);

        // If the connection was closed, don't try to send a close message.
        if (state == AbortState.ConnectionClosed)
        {
            Volatile.Write(ref _sendCloseOnDispose, 0);
        }

        // Store the first abort reason. Do it before setting _abortState.
        Interlocked.CompareExchange(ref _abortReason, abortException, null);

        if (Interlocked.CompareExchange(ref _abortState, (int)state, (int)AbortState.NotAborted) != (int)AbortState.NotAborted)
        {
            return; // Already aborted.
        }

        _receiveQueue.Writer.TryComplete();
        _sendWindowAvailableEvent.Release();

        if (state == AbortState.Closed ||
            state == AbortState.ConnectionClosed)
        {
            _ = _abortedTcs.CancelAsync(); // Don't block the receive loop.
        }
        else
        {
            _abortedTcs.Cancel();
        }
    }

    private int MoveDataFromSequenceToMemory(ref Sequence? sequence, Memory<byte>? buffer)
    {
        if (buffer != null)
        {
            int length = length = (int)Math.Min(buffer.Value.Length, sequence!.Length);
            sequence.AsReadOnlySequence().Slice(0, length).CopyTo(buffer.Value.Span);
            sequence.Remove(length);
            if (sequence.IsEmpty)
            {
                sequence.Dispose();
                sequence = null;
            }
            AdjustChannelWindow(length);
            return length;
        }
        else
        {
            AdjustChannelWindow((int)sequence!.Length);
            sequence.Dispose();
            sequence = null;
            return 0;
        }
    }

    private void AdjustChannelWindow(int bytesToAdd)
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
        int halfWindowSize = MaxWindowSize / 2;
        if (newWindow < halfWindowSize &&
            ((newWindow + bytesToAdd) >= halfWindowSize))
        {
            int adjust = MaxWindowSize - newWindow;
            Interlocked.Add(ref _receiveWindow, adjust);

            TrySendChannelWindowAdjustMessage((uint)adjust);
        }
    }

    internal void OnConnectionClosed()
        => Abort(AbortState.ConnectionClosed);

    internal void QueueReceivedPacket(Packet packet)
    {
        bool closeReceived = false;

        MessageId messageId = packet.MessageId!.Value;
        switch (messageId)
        {
            case MessageId.SSH_MSG_CHANNEL_REQUEST:
                HandleMsgChannelRequest(packet);
                return; // Don't queue.
            case MessageId.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                HandleMsgWindowAdjust(packet);
                return; // Don't queue.

            case MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                HandleMsgChannelOpenConfirmation(packet);
                _sendCloseOnDispose = 1;
                break;
            case MessageId.SSH_MSG_CHANNEL_CLOSE:
                closeReceived = true;
                break;
        }

        if (!_receiveQueue.Writer.TryWrite(packet))
        {
            packet.Dispose();

            // If the channel was disposed before we received SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            // a close message was not yet sent. Try sending one now.
            if (_sendCloseOnDispose == 1 && Volatile.Read(ref _disposed) != 0)
            {
                TrySendCloseOnDispose();
            }
        }

        if (closeReceived)
        {
            Abort(AbortState.Closed);
        }
    }

    // We send the close message when the channel is disposed because
    // the user musnt't be sending any more messages at that point.
    private void TrySendCloseOnDispose()
    {
        Debug.Assert(_disposed == 1);
        if (Interlocked.CompareExchange(ref _sendCloseOnDispose, 0, 1) == 1)
        {
            TrySendPacket(_sequencePool.CreateChannelCloseMessage(RemoteChannel), canSendWhenDisposed: true);
        }
    }

    private void TrySendPacket(Packet packet, bool canSendWhenDisposed = false)
    {
        // The lock ensures we don't try to send a packet from this channel
        // after we sent the close message.
        lock (_gate)
        {
            if (_disposed == 1 && !canSendWhenDisposed)
            {
                packet.Dispose();
            }
            else
            {
                _client.TrySendPacket(packet);
            }
        }
    }

    private async ValueTask<Packet> ReceivePacketAsync(CancellationToken ct)
    {
        // Allow reading while in the Closed state so we can receive the peer CLOSE message.
        // After that message, the channel is completed, and TryRead returns false.
        bool hasPacket = false;
        try
        {
            hasPacket = _abortState <= (int)AbortState.Closed &&
                        await _receiveQueue.Reader.WaitToReadAsync(ct).ConfigureAwait(false) &&
                        _abortState <= (int)AbortState.Closed;
        }
        catch (OperationCanceledException)
        {
            Cancel();

            ct.ThrowIfCancellationRequested();
        }

        if (!hasPacket || !_receiveQueue.Reader.TryRead(out Packet packet))
        {
            throw CreateCloseException();
        }

        return packet;
    }

    private void HandleMsgWindowAdjust(ReadOnlyPacket packet)
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
            _sendWindowAvailableEvent.Release();
        }
    }

    private void HandleMsgChannelOpenConfirmation(ReadOnlyPacket packet)
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
        SendMaxPacket = checked((int)reader.ReadUInt32()); // maximum packet size
    }

    private void HandleMsgChannelRequest(ReadOnlyPacket packet)
    {
        bool want_reply = ParseAndInterpretChannelRequest(packet);
        if (want_reply)
        {
            // If the request is not recognized or is not
            // supported for the channel, SSH_MSG_CHANNEL_FAILURE is returned.
            TrySendChannelFailureMessage();
        }
    }

    private bool ParseAndInterpretChannelRequest(ReadOnlyPacket packet)
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

        switch (request_type)
        {
            case "exit-status":
                /*
                    uint32    exit_status
                */
                ExitCode = unchecked((int)reader.ReadUInt32());
                reader.ReadEnd();
                break;
            case "exit-signal":
                /*
                    string    signal name (without the "SIG" prefix)
                    boolean   core dumped
                    string    error message in ISO-10646 UTF-8 encoding
                    string    language tag [RFC3066]
                */
                string exitSignal = reader.ReadUtf8String();
                ExitCode = 128; // TODO: assign based on exitSignal.
                reader.SkipBoolean();
                reader.SkipString();
                reader.SkipString();
                reader.ReadEnd();
                break;
        }

        return want_reply;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed != 0)
        {
            ThrowObjectDisposedException();
        }
    }

    private void ThrowObjectDisposedException()
        => throw CreateObjectDisposedException();

    private Exception CreateObjectDisposedException()
        => new ObjectDisposedException(_channelType.FullName);

    private void TrySendChannelFailureMessage()
        => TrySendPacket(_sequencePool.CreateChannelFailureMessage(RemoteChannel));

    private void TrySendChannelDataMessage(ReadOnlyMemory<byte> memory)
        => TrySendPacket(_sequencePool.CreateChannelDataMessage(RemoteChannel, memory));
}
