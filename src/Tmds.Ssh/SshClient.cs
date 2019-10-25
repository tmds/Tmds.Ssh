// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh
{
    public sealed partial class SshClient : IAsyncDisposable
    {
        private readonly SshClientSettings _settings;
        private readonly ILogger _logger;
        private readonly object _gate = new object();
        private readonly CancellationTokenSource _abortCts;    // Used to stop all operations
        private bool _disposed;
        private Channel<PendingSend>? _sendQueue;              // Multiple senders push into the queue
        private Task? _runningConnectionTask;                  // Task that encompasses all operations
        private Exception? _abortReason;                       // Reason why the client stopped
        private static readonly Exception ClosedByPeer = new Exception(); // Sentinel _abortReason
        private uint _nextChannelNumber;
        private readonly Dictionary<uint, SshClientChannelContext> _channels = new Dictionary<uint, SshClientChannelContext>();
        private readonly SequencePool _sequencePool = new SequencePool();
        private SemaphoreSlim? _keyReExchangeSemaphore;

        // TODO: maybe implement this using IValueTaskSource/ManualResetValueTaskSource
        struct PendingSend
        {
            public Packet Packet;
            public TaskCompletionSource<bool> TaskCompletion;
            public CancellationToken CancellationToken;
            public CancellationTokenRegistration CancellationTokenRegistration;
        }

        public SshClient(SshClientSettings settings, ILogger? logger = null)
        {
            ValidateSettings(settings);
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _logger = logger ?? NullLogger.Instance;
            _abortCts = new CancellationTokenSource();
        }

        private static void ValidateSettings(SshClientSettings settings)
        {
            // TODO: extend this...
            if (settings.Host == null)
            {
                throw new ArgumentNullException(nameof(settings.Host));
            }
        }

        public CancellationToken ConnectionClosed
        {
            get
            {
                // TODO: Throw if connectasync was never completed succesfully
                return _abortCts.Token;
            }
        }

        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            Task task;
            // ConnectAsync can be cancelled by calling DisposeAsync.
            lock (_gate)
            {
                ThrowIfDisposed();

                // SshClient allows a single ConnectAsync operation.
                if (_runningConnectionTask != null)
                {
                    ThrowHelper.ThrowInvalidOperation("Connect may be called once.");
                }

                // ConnectAsync waits for this Task.
                var connectionCompletedTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                task = connectionCompletedTcs.Task;

                // DisposeAsync waits for this Task to complete.
                _runningConnectionTask = RunConnectionAsync(cancellationToken, connectionCompletedTcs);
            }

            await task;
        }

        internal static async Task<SshConnection> EstablishConnectionAsync(ILogger logger, SequencePool sequencePool, SshClientSettings settings, CancellationToken ct)
        {
            Socket? socket = null;
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
                // Connect to the remote host
                logger.Connecting(settings.Host!, settings.Port);
                await socket.ConnectAsync(settings.Host!, settings.Port, ct);
                logger.ConnectionEstablished();
                socket.NoDelay = true;
                return new SocketSshConnection(logger, sequencePool, socket);
            }
            catch
            {
                socket?.Dispose();
                throw;
            }
        }

        private async Task RunConnectionAsync(CancellationToken connectCt, TaskCompletionSource<bool> connectTcs)
        {
            SshConnection? connection = null;
            var connectionInfo = new SshConnectionInfo();
            try
            {
                // Cancel when:
                // * DisposeAsync is called (_abortCts)
                // * CancellationToken parameter from ConnectAsync (connectCt)
                // * Timeout from ConnectionSettings (ConnectTimeout)
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(connectCt, _abortCts.Token);
                connectCts.CancelAfter(_settings.ConnectTimeout);

                // Connect to the remote host
                connection = await _settings.EstablishConnectionAsync(_logger, _sequencePool, _settings, connectCts.Token);

                // Setup ssh connection
                if (!_settings.NoProtocolVersionExchange)
                {
                    await _settings.ExchangeProtocolVersionAsync(connection, connectionInfo, _logger, _settings, connectCts.Token);
                }
                if (!_settings.NoKeyExchange)
                {
                    using Packet localExchangeInitMsg = KeyExchange.CreateKeyExchangeInitMessage(_sequencePool, _logger, _settings);
                    await connection.SendPacketAsync(localExchangeInitMsg, connectCts.Token);
                    {
                        using Packet remoteExchangeInitMsg = await connection.ReceivePacketAsync(connectCts.Token);
                        if (remoteExchangeInitMsg.IsEmpty)
                        {
                            ThrowHelper.ThrowProtocolUnexpectedPeerClose();
                        }
                        await _settings.ExchangeKeysAsync(connection, localExchangeInitMsg, remoteExchangeInitMsg, _logger, _settings, connectionInfo, connectCts.Token);
                    }
                }
                if (!_settings.NoUserAuthentication)
                {
                    await _settings.AuthenticateUserAsync(connection, _logger, _settings, connectionInfo, connectCts.Token);
                }

                // Allow sending.
                _sendQueue = Channel.CreateUnbounded<PendingSend>(new UnboundedChannelOptions
                {
                    SingleWriter = false,
                    SingleReader = true,
                    AllowSynchronousContinuations = true
                });
                // ConnectAsync completed successfully.
                connectTcs.SetResult(true);
            }
            catch (Exception e)
            {
                connection?.Dispose();

                // In case the operation was canceled, change the exception based on the
                // token that triggered the cancellation.
                if (e is OperationCanceledException)
                {
                    if (connectCt.IsCancellationRequested)
                    {
                        connectTcs.SetCanceled();
                        return;
                    }
                    else if (_abortCts.IsCancellationRequested)
                    {
                        e = NewObjectDisposedException();
                    }
                    else
                    {
                        e = new TimeoutException();
                    }
                }

                // ConnectAsync failed.
                connectTcs.SetException(e);
                return;
            }

            await HandleConnectionAsync(connection, connectionInfo);
        }

        private async Task HandleConnectionAsync(SshConnection connection, SshConnectionInfo connectionInfo)
        {
            try
            {
                Task sendTask = SendLoopAsync(connection);
                Task receiveTask = ReceiveLoopAsync(connection, connectionInfo);
                await Task.WhenAll(sendTask, receiveTask);
            }
            catch (Exception e) // Unexpected: the continuation doesn't throw.
            {
                Abort(e);
            }
            finally
            {
                connection.Dispose();
            }
        }

        internal ChannelContext CreateChannel(CancellationToken ct = default)
        {
            lock (_gate)
            {
                ThrowIfNotConnected();

                uint channelNumber = unchecked(_nextChannelNumber++); // TODO: handle numbering, including OnChannelClosed.
                var channelContext = new SshClientChannelContext(this, channelNumber, ct);
                _channels[channelNumber] = channelContext;

                return channelContext;
            }
        }

        private ValueTask SendPacketAsync(Packet packet, CancellationToken ct)
        {
            Channel<PendingSend>? sendQueue = _sendQueue;

            if (sendQueue == null)
            {
                // Trying to send before ConnectAsync completed.
                ThrowHelper.ThrowInvalidOperation("Not connected");
            }

            if (_abortReason != null)
            {
                return new ValueTask(Task.FromCanceled(_abortCts.Token));
            }

            try
            {
                var cts = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                var send = new PendingSend
                {
                    Packet = packet,
                    TaskCompletion = cts,
                    CancellationToken = ct,
                    CancellationTokenRegistration = ct.UnsafeRegister(s => ((TaskCompletionSource<bool>)s!).SetCanceled(), cts)
                };
                bool written = sendQueue!.Writer.TryWrite(send);
                if (!written)
                {
                    // SendLoopAsync stopped.
                    send.CancellationTokenRegistration.Dispose();
                    if (!send.TaskCompletion.Task.IsCanceled)
                    {
                        send.TaskCompletion.SetCanceled();
                    }
                    packet.Dispose();
                }
                return new ValueTask(cts.Task);
            }
            catch (Exception e) // This shouldn't happen.
            {
                packet.Dispose();
                Abort(e);
                throw;
            }
        }

        private async Task SendLoopAsync(SshConnection connection)
        {
            CancellationToken abortToken = _abortCts.Token;
            try
            {
                while (true)
                {
                    PendingSend send = await _sendQueue!.Reader.ReadAsync(abortToken); // TODO: maybe use ReadAllAsync
                    try
                    {
                        // Disable send.CancellationToken.
                        send.CancellationTokenRegistration.Dispose();
                        if (!send.TaskCompletion.Task.IsCanceled)
                        {
                            // If we weren't canceled by send.CancellationToken, do the send.
                            // We use abortToken instead of send.CancellationToken because
                            // we can't allow partial sends unless we're aborting the connection.
                            await connection.SendPacketAsync(send.Packet, abortToken);

                            SemaphoreSlim? keyExchangeSemaphore = null;
                            if (send.Packet.MessageId == MessageId.SSH_MSG_KEXINIT)
                            {
                                keyExchangeSemaphore = _keyReExchangeSemaphore;
                                _keyReExchangeSemaphore = null;
                            }

                            send.TaskCompletion.SetResult(true);

                            // Don't send any more packets until Key Re-Exchange completed.
                            if (keyExchangeSemaphore != null)
                            {
                                await keyExchangeSemaphore.WaitAsync(abortToken);
                                keyExchangeSemaphore.Dispose();
                            }
                        }
                    }
                    catch (Exception e) // SendPacket failed or connection aborted.
                    {
                        Abort(e);

                        // The sender isn't responsible for the fail,
                        // report this as canceled.
                        send.TaskCompletion.SetCanceled();
                    }
                }
            }
            catch (Exception e) // Happens on Abort.
            {
                // Ensure Abort is called so further SendPacketAsync calls return Canceled.
                Abort(e); // In case the Exception was not caused by Abort.
            }
            finally
            {
                // Empty _sendQueue and prevent new sends.
                if (_sendQueue != null)
                {
                    _sendQueue.Writer.Complete();

                    while (_sendQueue.Reader.TryRead(out PendingSend send))
                    {
                        send.CancellationTokenRegistration.Dispose();
                        if (!send.TaskCompletion.Task.IsCanceled)
                        {
                            send.TaskCompletion.SetCanceled();
                        }
                    }
                }
            }
        }

        private async Task ReceiveLoopAsync(SshConnection connection, SshConnectionInfo connectionInfo)
        {
            CancellationToken abortToken = _abortCts.Token;
            while (true)
            {
                using var packet = await connection.ReceivePacketAsync(abortToken, maxLength: Constants.MaxPacketLength);
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
                        try
                        {
                            // When we send SSH_MSG_KEXINIT, we can't send other packets until key exchange completes.
                            // This is implemented using _keyReExchangeSemaphore.
                            var keyExchangeSemaphore = new SemaphoreSlim(0, 1);
                            _keyReExchangeSemaphore = keyExchangeSemaphore;
                            // this will await _keyReExchangeSemaphore and set it to null.
                            using Packet clientKexInitMsg = KeyExchange.CreateKeyExchangeInitMessage(_sequencePool, _logger, _settings);
                            try
                            {
                                await SendPacketAsync(clientKexInitMsg, abortToken);
                            }
                            catch
                            {
                                _keyReExchangeSemaphore.Dispose();
                                _keyReExchangeSemaphore = null;
                                throw;
                            }
                            await _settings.ExchangeKeysAsync(connection, clientKexInitMsg, serverKexInitMsg: packet, _logger, _settings, connectionInfo, abortToken);
                            keyExchangeSemaphore.Release();
                        }
                        finally
                        {
                            packet.Dispose();
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
                        lock (_channels)
                        {
                            var channelExecution = _channels[channelNumber];
                            channelExecution.QueueReceivedPacket(packet.Move());
                        }
                        break;
                    case MessageId.SSH_MSG_GLOBAL_REQUEST:
                        await HandleGlobalRequestAsync(packet);
                        break;
                    case MessageId.SSH_MSG_DEBUG:
                        HandleDebugMessage(packet);
                        break;
                    case MessageId.SSH_MSG_DISCONNECT:
                        HandleDisconnectMessage(packet);
                        break;
                    default:
                        ThrowHelper.ThrowProtocolUnexpectedMessageId(msgId);
                        break;
                }
            }

            static uint GetChannelNumber(Packet packet)
            {
                var reader = packet.GetReader();
                reader.ReadMessageId();
                return reader.ReadUInt32();
            }
        }

        private void HandleDisconnectMessage(Packet packet)
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

            throw new DisconnectException(description); // TODO: pass more fields.
        }

        private void HandleDebugMessage(Packet packet)
        {
            /*
                byte      SSH_MSG_DEBUG
                boolean   always_display
                string    message in ISO-10646 UTF-8 encoding [RFC3629]
                string    language tag [RFC3066]
             */
            var reader = packet.GetReader();
            reader.ReadMessageId(MessageId.SSH_MSG_DEBUG);
            bool always_display = reader.ReadBoolean();
            string message = reader.ReadUtf8String(); // TODO: pass this to the user, maybe.
            reader.SkipString();
            reader.ReadEnd();
        }

        private async ValueTask HandleGlobalRequestAsync(Packet packet)
        {
            // If the recipient does not recognize or support the request, it simply
            // responds with SSH_MSG_REQUEST_FAILURE.
            using var response = RentPacket();
            response.GetWriter().WriteMessageId(MessageId.SSH_MSG_REQUEST_FAILURE);
            await SendPacketAsync(response, _abortCts.Token);
        }

        // This method is for doing a clean shutdown which may involve sending some messages over the wire.
        // public async Task DisconnectAsync(CancellationToken cancellationToken)
        // {
        //     // TODO: SshClientSettings needs an upper bound time for this method (e.g. SshClientSettings.DisconnectTimeout)

        //     // In a finally block, this method calls Dispose.
        // }

        // This method will just cut the connection.
        public async ValueTask DisposeAsync()
        {
            Task? runningConnectionTask = null;
            lock (_gate)
            {
                _disposed = true;
                runningConnectionTask = _runningConnectionTask;
            }
            Abort(NewObjectDisposedException());
            if (runningConnectionTask != null)
            {
                await runningConnectionTask;
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw NewObjectDisposedException();
            }
        }

        private Exception NewObjectDisposedException()
        {
            return new ObjectDisposedException(GetType().FullName);
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
                _abortCts.Cancel();
            }
        }

        private Packet RentPacket()
            => _sequencePool.RentPacket();

        private void ThrowNewConnectionClosedException()
        {
            if (_abortReason == null)
            {
                ThrowHelper.ThrowInvalidOperation("Connection not closed");
            }
            if (_abortReason == ClosedByPeer)
            {
                throw new ConnectionClosedException("Connection closed by peer.");
            }
            else
            {
                throw new ConnectionClosedException($"Connection closed: {_abortReason!.Message}", _abortReason);
            }
        }

        private void OnChannelClosed(SshClientChannelContext context)
        {
            lock (_channels)
            {
                _channels.Remove(context.LocalChannel);
            }
        }

        public void ThrowIfNotConnected()
        {
            ThrowIfDisposed();

            if (_abortReason != null)
            {
                ThrowNewConnectionClosedException();
            }

            if (_sendQueue == null)
            {
                ThrowHelper.ThrowInvalidOperation("Not connected.");
            }
        }
    }
}
