// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh;

sealed partial class SshSession : ISshClientImplementation
{
    private static readonly Exception ClosedByPeer = new Exception(); // Sentinel _abortReason
    private static readonly ObjectDisposedException DisposedException = SshClient.NewObjectDisposedException();

    private readonly SshClient _client;
    private readonly SshClientSettings _settings;
    private readonly ILogger _logger;
    private readonly object _gate = new object();
    private readonly CancellationTokenSource _abortCts;    // Used to stop all operations
    private bool _disposed;
    private Channel<Packet>? _sendQueue;              // Multiple senders push into the queue
    private Task? _runningConnectionTask;                  // Task that encompasses all operations
    private Exception? _abortReason;                       // Reason why the client stopped
    private readonly Dictionary<uint, SshChannel> _channels = new Dictionary<uint, SshChannel>();
    private readonly SequencePool _sequencePool = new SequencePool();
    private SemaphoreSlim? _keyReExchangeSemaphore;
    private const int BitsPerAllocatedItem = sizeof(int) * 8;
    private readonly List<int> _allocatedChannels = new List<int>();

    public SshConnectionInfo ConnectionInfo { get; }

    internal SshSession(SshClientSettings settings, SshClient client)
    {
        _abortCts = new CancellationTokenSource();

        _settings = settings;

        ConnectionInfo = new SshConnectionInfo()
        {
            Host = _settings.Host,
            Port = _settings.Port
        };

        _logger = NullLogger.Instance;
        _client = client;
    }

    public CancellationToken ConnectionClosed
    {
        get
        {
            ThrowIfDisposed();
            ThrowIfNeverConnected();

            return _abortCts.Token;
        }
    }

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        Task task;
        // ConnectAsync can be cancelled by calling Dispose.
        lock (_gate)
        {
            ThrowIfDisposed();

            // SshSession allows a single ConnectAsync operation.
            if (_runningConnectionTask != null)
            {
                ThrowHelper.ThrowInvalidOperation("Connect may be called once.");
            }

            // ConnectAsync waits for this Task.
            var connectionCompletedTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            task = connectionCompletedTcs.Task;

            _runningConnectionTask = RunConnectionAsync(ct, connectionCompletedTcs);
        }

        await task;
    }

    internal static async Task<SshConnection> EstablishConnectionAsync(ILogger logger, SequencePool sequencePool, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct)
    {
        Socket? socket = null;
        try
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
            // Connect to the remote host
            logger.Connecting(settings.Host, settings.Port);
            await socket.ConnectAsync(settings.Host, settings.Port, ct).ConfigureAwait(false);
            connectionInfo.IPAddress = (socket.RemoteEndPoint as IPEndPoint)?.Address;
            logger.ConnectionEstablished();
            socket.NoDelay = true;
            return new SocketSshConnection(logger, sequencePool, socket);
        }
        catch (Exception ex)
        {
            socket?.Dispose();

            // ConnectAsync may throw ODE for cancellation
            // when the connection is made just before the token gets cancelled.
            if (ex is ObjectDisposedException)
            {
                ct.ThrowIfCancellationRequested();
            }

            throw;
        }
    }

    private async Task RunConnectionAsync(CancellationToken connectCt, TaskCompletionSource<bool> connectTcs)
    {
        SshConnection? connection = null;
        try
        {
            // Cancel when:
            // * Dispose is called (_abortCts)
            // * CancellationToken parameter from ConnectAsync (connectCt)
            // * Timeout from ConnectionSettings (ConnectTimeout)
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(connectCt, _abortCts.Token);
            connectCts.CancelAfter(_settings.ConnectTimeout);

            // Connect to the remote host
            connection = await _settings.EstablishConnectionAsync(_logger, _sequencePool, _settings, ConnectionInfo, connectCts.Token).ConfigureAwait(false);

            // Setup ssh connection
            if (!_settings.NoProtocolVersionExchange)
            {
                await _settings.ExchangeProtocolVersionAsync(connection, ConnectionInfo, _logger, _settings, connectCts.Token).ConfigureAwait(false);
            }
            if (!_settings.NoKeyExchange)
            {
                using Packet localExchangeInitMsg = _sequencePool.CreateKeyExchangeInitMessage(_settings);
                await connection.SendPacketAsync(localExchangeInitMsg.Clone(), connectCts.Token).ConfigureAwait(false);
                {
                    using Packet remoteExchangeInitMsg = await connection.ReceivePacketAsync(connectCts.Token).ConfigureAwait(false);
                    if (remoteExchangeInitMsg.IsEmpty)
                    {
                        ThrowHelper.ThrowProtocolUnexpectedPeerClose();
                    }
                    await _settings.ExchangeKeysAsync(connection, localExchangeInitMsg, remoteExchangeInitMsg, _logger, _settings, ConnectionInfo, connectCts.Token).ConfigureAwait(false);
                }
            }
            if (!_settings.NoUserAuthentication)
            {
                await _settings.AuthenticateUserAsync(connection, _logger, _settings, ConnectionInfo, connectCts.Token).ConfigureAwait(false);
            }

            // Allow sending.
            _sendQueue = Channel.CreateUnbounded<Packet>(new UnboundedChannelOptions
            {
                SingleWriter = false, // Enable different channels to write concurrently.
                SingleReader = true,  // Only reader is the send loop.
                AllowSynchronousContinuations = true // Allow direct sending when send is queued.
            });
            // ConnectAsync completed successfully.
            connectTcs.SetResult(true);
        }
        catch (Exception e)
        {
            connection?.Dispose();

            // In case the operation was canceled, change the exception based on the
            // token that triggered the cancellation.
            // We want to throw ConnectFailedException, except when the user CancellationToken was cancelled.
            if (e is OperationCanceledException)
            {
                if (connectCt.IsCancellationRequested)
                {
                    // Throw OperationCancelledException.
                    connectTcs.SetCanceled();
                    return;
                }
                else if (_abortCts.IsCancellationRequested)
                {
                    e = new ConnectFailedException(ConnectFailedReason.ConnectionAborted, $"The connection was aborted: {e.Message}", ConnectionInfo, _abortReason!);
                }
                else
                {
                    e = new ConnectFailedException(ConnectFailedReason.Timeout, "The connect operation timed out.", ConnectionInfo, new TimeoutException());
                }
            }
            else if (e is ConnectFailedException)
            { }
            else
            {
                e = new ConnectFailedException(ConnectFailedReason.Unknown, $"An exception occurred: {e.Message}.", ConnectionInfo, e);
            }

            // ConnectAsync failed.
            connectTcs.SetException(e);
            return;
        }

        await HandleConnectionAsync(connection, ConnectionInfo).ConfigureAwait(false);
    }

    private async Task HandleConnectionAsync(SshConnection connection, SshConnectionInfo ConnectionInfo)
    {
        Task sendTask = SendLoopAsync(connection);
        Task receiveTask = ReceiveLoopAsync(connection, ConnectionInfo);
        await Task.WhenAll(sendTask, receiveTask).ConfigureAwait(false);
        connection.Dispose();

        // The lock guards adding new channels
        // and channels can't be once the connection aborted.
        lock (_gate)
        {
            Debug.Assert(_abortReason is not null);
        }
        foreach (var channel in _channels)
        {
            channel.Value.OnConnectionClosed();
        }
    }

    private SshChannel CreateChannel(Type channelType, Action<SshChannel>? onAbort = null)
    {
        lock (_gate)
        {
            ThrowIfNotConnected();

            uint channelNumber = AllocateChannel();
            var channelContext = new SshChannel(this, _sequencePool, channelNumber, channelType, onAbort);
            _channels[channelNumber] = channelContext;

            return channelContext;
        }
    }

    internal void TrySendPacket(Packet packet)
    {
        Channel<Packet>? sendQueue = _sendQueue;

        if (sendQueue == null)
        {
            // Trying to send before ConnectAsync completed.
            ThrowNeverConnected();
        }

        if (!sendQueue!.Writer.TryWrite(packet))
        {
            packet.Dispose();
        }
    }

    private async Task SendLoopAsync(SshConnection connection)
    {
        try
        {
            CancellationToken abortToken = _abortCts.Token;
            while (true)
            {
                using var pkt = await _sendQueue!.Reader.ReadAsync(abortToken).ConfigureAwait(false);

                bool isKexInit = pkt.MessageId == MessageId.SSH_MSG_KEXINIT;

                // If we weren't canceled by send.CancellationToken, do the send.
                // We use abortToken instead of send.CancellationToken because
                // we can't allow partial sends unless we're aborting the connection.
                await connection.SendPacketAsync(pkt.Move(), abortToken).ConfigureAwait(false);

                if (isKexInit)
                {
                    SemaphoreSlim? kexInitSent = _keyReExchangeSemaphore;
                    Debug.Assert(kexInitSent is not null);
                    // Assign _keyReExchangeSemaphore before releasing kexInitSent.
                    var keyExchangeComplete = _keyReExchangeSemaphore = new SemaphoreSlim(0, 1);
                    // Signal to the receive loop the packet is sent.
                    kexInitSent.Release();
                    // Wait for the receive loop to complete the key exchange.
                    await keyExchangeComplete.WaitAsync(abortToken).ConfigureAwait(false);
                    await Task.Yield(); // Move of the receive loop.
                }
            }
        }
        catch (Exception e) // Happens on Abort.
        {
            Abort(e); // In case the Exception was not caused by Abort.
        }
        finally
        {
            // Empty _sendQueue and prevent new sends.
            if (_sendQueue != null)
            {
                _sendQueue.Writer.Complete();

                while (_sendQueue.Reader.TryRead(out Packet packet))
                {
                    packet.Dispose();
                }
            }
        }
    }

    private async Task ReceiveLoopAsync(SshConnection connection, SshConnectionInfo ConnectionInfo)
    {
        try
        {
            CancellationToken abortToken = _abortCts.Token;
            while (true)
            {
                using var packet = await connection.ReceivePacketAsync(abortToken, maxLength: Constants.MaxPacketLength).ConfigureAwait(false);
                if (packet.IsEmpty)
                {
                    Abort(ClosedByPeer);
                    break;
                }

                MessageId msgId = packet.MessageId!.Value;

                // Connection Protocol: https://tools.ietf.org/html/rfc4254.
                switch (msgId)
                {
                    case MessageId.SSH_MSG_KEXINIT:
                        // Key Re-Exchange: https://tools.ietf.org/html/rfc4253#section-9.
                        // The peer requested a key exchange. We queue a SSH_MSG_KEXINIT and when the send loop detects it
                        // it will stop sending other packets until we release the key exchange semaphore to signal the key exchange is completed.
                        {
                            using Packet clientKexInitMsg = _sequencePool.CreateKeyExchangeInitMessage(_settings);

                            // Assign _keyReExchangeSemaphore before sending packet through the send queue.
                            var kexInitSent = _keyReExchangeSemaphore = new SemaphoreSlim(0, 1);
                            // Wait for the send loop to send the packet.
                            TrySendPacket(clientKexInitMsg.Clone());
                            await kexInitSent.WaitAsync(abortToken).ConfigureAwait(false);

                            // Send loop has re-assigned _keyReExchangeSemaphore for us to signal kex completion.
                            var kexComplete = _keyReExchangeSemaphore;
                            _keyReExchangeSemaphore = null;
                            // The send loop waits for us to signal kex completion.
                            try
                            {
                                await _settings.ExchangeKeysAsync(connection, clientKexInitMsg, serverKexInitMsg: packet, _logger, _settings, ConnectionInfo, abortToken).ConfigureAwait(false);
                            }
                            finally
                            {
                                kexComplete.Release();
                            }
                        }
                        break;
                    case MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                    case MessageId.SSH_MSG_CHANNEL_OPEN_FAILURE:
                    case MessageId.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                    case MessageId.SSH_MSG_CHANNEL_DATA:
                    case MessageId.SSH_MSG_CHANNEL_EXTENDED_DATA:
                    case MessageId.SSH_MSG_CHANNEL_EOF:
                    case MessageId.SSH_MSG_CHANNEL_CLOSE:
                    case MessageId.SSH_MSG_CHANNEL_REQUEST:
                    case MessageId.SSH_MSG_CHANNEL_SUCCESS:
                    case MessageId.SSH_MSG_CHANNEL_FAILURE:
                        uint channelNumber = GetChannelNumber(packet);
                        SshChannel channel;
                        lock (_gate)
                        {
                            channel = _channels[channelNumber];
                        }
                        channel.QueueReceivedPacket(packet.Move());
                        if (msgId is MessageId.SSH_MSG_CHANNEL_CLOSE or
                                     MessageId.SSH_MSG_CHANNEL_OPEN_FAILURE)
                        {
                            lock (_gate)
                            {
                                FreeChannel(channelNumber);
                                _channels.Remove(channelNumber);
                            }
                        }
                        break;
                    case MessageId.SSH_MSG_GLOBAL_REQUEST:
                        TrySendPacket(_sequencePool.CreateRequestFailureMessage());
                        break;
                    case MessageId.SSH_MSG_DEBUG:
                        break;
                    case MessageId.SSH_MSG_DISCONNECT:
                        HandleDisconnectMessage(packet);
                        break;
                    default:
                        ThrowHelper.ThrowProtocolUnexpectedMessageId(msgId);
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            Abort(ex);
        }

        static uint GetChannelNumber(ReadOnlyPacket packet)
        {
            var reader = packet.GetReader();
            reader.ReadMessageId();
            return reader.ReadUInt32();
        }
    }

    private void HandleDisconnectMessage(ReadOnlyPacket packet)
    {
        /*
            byte      SSH_MSG_DISCONNECT
            uint32    reason code
            string    description in ISO-10646 UTF-8 encoding [RFC3629]
            string    language tag [RFC3066]
         */
        var reader = packet.GetReader();
        reader.ReadMessageId(MessageId.SSH_MSG_DISCONNECT);
        uint reason_code = reader.ReadUInt32();
        string description = reader.ReadUtf8String();
        reader.SkipString();
        reader.ReadEnd();

        throw new DisconnectException((DisconnectReason)reason_code, description);
    }

    // This method will just cut the connection.
    public void Dispose()
    {
        Task? runningConnectionTask = null;
        lock (_gate)
        {
            _disposed = true;
            runningConnectionTask = _runningConnectionTask;
        }
        if (_abortReason == null)
        {
            Abort(DisposedException);
        }
        if (runningConnectionTask != null)
        {
            runningConnectionTask.GetAwaiter().GetResult();
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw SshClient.NewObjectDisposedException();
        }
    }

    private void Abort(Exception reason)
    {
        if (reason == null)
        {
            ThrowHelper.ThrowArgumentNull(nameof(reason));
        }

        // Capture the first exception to call Abort.
        // Once we cancel the token, we'll get more Abort calls.
        if (Interlocked.CompareExchange(ref _abortReason, reason, null) == null)
        {
            // Notify the SshClient about the disconnect before making other changes
            // that will propagate to the user.
            // This ensures we'll create a new session when the user retries an operation (when AutoReconnect is set).
            _client.OnSessionDisconnect(this);

            _abortCts.Cancel();

            lock (_gate)
            { }
        }
    }

    internal Packet RentPacket()
        => _sequencePool.RentPacket();

    private void ThrowNewConnectionClosedException()
    {
        throw CreateCloseException();
    }

    internal Exception CreateCloseException()
    {
        if (_abortReason == null)
        {
            ThrowHelper.ThrowInvalidOperation("Connection not closed");
        }
        if (_abortReason == ClosedByPeer)
        {
            return new SshConnectionClosedException(SshConnectionClosedException.ConnectionClosedByPeer);
        }
        else if (_abortReason == DisposedException)
        {
            return new SshConnectionClosedException(SshConnectionClosedException.ConnectionClosedByDispose, _abortReason);
        }
        else if (_abortReason is DisconnectException)
        {
            return new SshConnectionClosedException(SshConnectionClosedException.ConnectionClosedByPeer, _abortReason);
        }
        else
        {
            return new SshConnectionClosedException(SshConnectionClosedException.ConnectionClosedByAbort, _abortReason);
        }
    }

    internal void ThrowIfNotConnected()
    {
        ThrowIfDisposed();

        if (_abortReason != null)
        {
            ThrowNewConnectionClosedException();
        }

        ThrowIfNeverConnected();
    }

    private void ThrowIfNeverConnected()
    {
        if (!HasConnected)
        {
            ThrowNeverConnected();
        }
    }

    private void ThrowNeverConnected()
    {
        ThrowHelper.ThrowInvalidOperation("Not connected.");
    }

    private uint AllocateChannel()
    {
        for (int i = 0; i < _allocatedChannels.Count; i++)
        {
            int v = _allocatedChannels[i];
            if (v != -1)
            {
                for (int j = 0; j < BitsPerAllocatedItem; j++)
                {
                    if ((v & 1) == 0)
                    {
                        int mask = 1 << j;
                        _allocatedChannels[i] = _allocatedChannels[i] | mask;
                        return unchecked((uint)(i * BitsPerAllocatedItem + j));
                    }
                    v >>= 1;
                }
            }
        }
        _allocatedChannels.Add(1);
        return unchecked((uint)((_allocatedChannels.Count - 1) * BitsPerAllocatedItem));
    }

    private void FreeChannel(uint nr)
    {
        int nri = unchecked((int)nr);
        int i = nri / BitsPerAllocatedItem;
        int mask = 1 << (nri % BitsPerAllocatedItem);
        _allocatedChannels[i] = _allocatedChannels[i] & ~mask;
    }

    public async Task<ISshChannel> OpenRemoteProcessChannelAsync(Type channelType, string command, CancellationToken cancellationToken)
    {
        SshChannel channel = CreateChannel(channelType);
        try
        {
            // Open the session channel.
            {
                channel.TrySendChannelOpenSessionMessage();
                await channel.ReceiveChannelOpenConfirmationAsync(cancellationToken).ConfigureAwait(false);
            }

            // Request command execution.
            {
                channel.TrySendExecCommandMessage(command);
                await channel.ReceiveChannelRequestSuccessAsync("Failed to execute command.", cancellationToken).ConfigureAwait(false);
            }

            return channel;
        }
        catch
        {
            channel.Dispose();
            throw;
        }
    }

    public async Task<ISshChannel> OpenTcpConnectionChannelAsync(Type channelType, string host, int port, CancellationToken cancellationToken)
    {
        SshChannel channel = CreateChannel(channelType);
        try
        {
            IPAddress originatorIP = IPAddress.Any;
            int originatorPort = 0;
            channel.TrySendChannelOpenDirectTcpIpMessage(host, (uint)port, originatorIP, (uint)originatorPort);
            await channel.ReceiveChannelOpenConfirmationAsync(cancellationToken).ConfigureAwait(false);

            return channel;
        }
        catch
        {
            channel.Dispose();
            throw;
        }
    }

    public async Task<ISshChannel> OpenUnixConnectionChannelAsync(Type channelType, string path, CancellationToken cancellationToken)
    {
        SshChannel channel = CreateChannel(channelType);
        try
        {
            channel.TrySendChannelOpenDirectStreamLocalMessage(path);
            await channel.ReceiveChannelOpenConfirmationAsync(cancellationToken).ConfigureAwait(false);

            return channel;
        }
        catch
        {
            channel.Dispose();
            throw;
        }
    }

    public async Task<ISshChannel> OpenSftpClientChannelAsync(Action<SshChannel> onAbort, CancellationToken cancellationToken)
    {
        SshChannel channel = CreateChannel(typeof(SftpClient), onAbort);
        try
        {
            // Open the session channel.
            {
                channel.TrySendChannelOpenSessionMessage();
                await channel.ReceiveChannelOpenConfirmationAsync(cancellationToken).ConfigureAwait(false);
            }

            // Request subsystem execution.
            {
                channel.TrySendExecSubsystemMessage("sftp");
                await channel.ReceiveChannelRequestSuccessAsync("Failed to execute sftp subsystem.", cancellationToken).ConfigureAwait(false);
            }

            return channel;
        }
        catch
        {
            channel.Dispose();
            throw;
        }
    }

    // For testing.
    internal void ForceConnectionClose()
    {
        Debug.Assert(_runningConnectionTask is not null);
        Abort(new Exception("Connection closed by test."));
        _runningConnectionTask.WaitAsync(TimeSpan.FromSeconds(30)).GetAwaiter().GetResult();
    }

    private bool HasConnected =>
        _sendQueue != null;
}
