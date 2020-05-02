// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh
{
    public sealed partial class SshClient : IDisposable
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
        private readonly Dictionary<uint, SshClientChannelContext> _channels = new Dictionary<uint, SshClientChannelContext>();
        private readonly SequencePool _sequencePool = new SequencePool();
        private SemaphoreSlim? _keyReExchangeSemaphore;
        private const int BitsPerAllocatedItem = sizeof(int) * 8;
        private readonly List<int> _allocatedChannels = new List<int>();

        // MAYDO: maybe implement this using IValueTaskSource/ManualResetValueTaskSource
        struct PendingSend
        {
            public Packet Packet;
            public TaskCompletionSource<bool> TaskCompletion;
            public CancellationTokenRegistration Ctr1;
            public CancellationTokenRegistration Ctr2;
        }

        public SshConnectionInfo ConnectionInfo { get; }

        public SshClient(string destination, Action<SshClientSettings>? configure = null)
        {
            _abortCts = new CancellationTokenSource();

            _settings = CreateSettingsForDestination(destination);
            if (configure == null)
            {
                _settings.Credentials.Add(new IdentityFileCredential(IdentityFileCredential.RsaIdentityFile));
            }
            else
            {
                configure?.Invoke(_settings);
            }
            _logger = _settings.Logger ?? NullLogger.Instance;
            ValidateSettings(_settings);

            ConnectionInfo = new SshConnectionInfo()
            {
                Port = _settings.Port,
                Host = _settings.Host
            };
        }

        private static SshClientSettings CreateSettingsForDestination(string destination)
        {
            if (destination == null)
            {
                ThrowHelper.ThrowArgumentNull(nameof(destination));
            }
            string host = destination;
            int port = 22;
            int colonPos = host.IndexOf(":");
            if (colonPos != -1)
            {
                port = int.Parse(host.Substring(colonPos + 1));
                host = host.Substring(0, colonPos);
            }
            int atPos = host.IndexOf("@");
            string username;
            if (atPos != -1)
            {
                username = host.Substring(0, atPos);
                host = host.Substring(atPos + 1);
            }
            else
            {
                username = string.Empty;
            }
            return new SshClientSettings(username, host, port);
        }

        private static void ValidateSettings(SshClientSettings settings)
        {
            // TODO: extend this...
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
            catch
            {
                socket?.Dispose();
                throw;
            }
        }

        private async Task RunConnectionAsync(CancellationToken connectCt, TaskCompletionSource<bool> connectTcs)
        {
            SshConnection? connection = null;
            try
            {
                // Cancel when:
                // * DisposeAsync is called (_abortCts)
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
                    using Packet localExchangeInitMsg = KeyExchange.CreateKeyExchangeInitMessage(_sequencePool, _logger, _settings);
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
                _sendQueue = Channel.CreateUnbounded<PendingSend>(new UnboundedChannelOptions
                {
                    SingleWriter = false,
                    SingleReader = true,
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
                        e = new ConnectFailedException(ConnectFailedReason.Timeout, "The connect operation timed out.", ConnectionInfo);
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
            try
            {
                Task sendTask = SendLoopAsync(connection);
                Task receiveTask = ReceiveLoopAsync(connection, ConnectionInfo);
                await Task.WhenAll(sendTask, receiveTask).ConfigureAwait(false);
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

        internal ChannelContext CreateChannel()
        {
            lock (_gate)
            {
                ThrowIfNotConnected();

                uint channelNumber = AllocateChannel();
                var channelContext = new SshClientChannelContext(this, channelNumber);
                _channels[channelNumber] = channelContext;

                return channelContext;
            }
        }

        private ValueTask SendPacketAsync(Packet packet, CancellationToken ct1 = default, CancellationToken ct2 = default)
        {
            using var pkt = packet.Move();
            Channel<PendingSend>? sendQueue = _sendQueue;

            if (sendQueue == null)
            {
                // Trying to send before ConnectAsync completed.
                ThrowHelper.ThrowInvalidOperation("Not connected.");
            }

            if (_abortReason != null)
            {
                return new ValueTask(Task.FromException(NewConnectionClosedException()));
            }

            try
            {
                var cts = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                var send = new PendingSend
                {
                    Packet = pkt.Move(),
                    TaskCompletion = cts,
                    Ctr1 = ct1.Register(s => ((TaskCompletionSource<bool>)s!).TrySetCanceled(), cts),
                    Ctr2 = ct2.Register(s => ((TaskCompletionSource<bool>)s!).TrySetCanceled(), cts)
                };

                bool written = sendQueue!.Writer.TryWrite(send);
                if (!written)
                {
                    // SendLoopAsync stopped.
                    send.Packet.Dispose();
                    send.Ctr1.Dispose();
                    send.Ctr2.Dispose();
                    if (!send.TaskCompletion.Task.IsCompleted)
                    {
                        send.TaskCompletion.SetException(NewConnectionClosedException());
                    }
                }

                return new ValueTask(cts.Task);
            }
            catch (Exception e) // This shouldn't happen.
            {
                Abort(e);

                return new ValueTask(Task.FromException(NewConnectionClosedException()));
            }
        }

        private async Task SendLoopAsync(SshConnection connection)
        {
            CancellationToken abortToken = _abortCts.Token;
            try
            {
                while (true)
                {
                    // MAYDO: maybe use ReadAllAsync and move this into the SshConnection.
                    PendingSend send = await _sendQueue!.Reader.ReadAsync(abortToken).ConfigureAwait(false);
                    using var pkt = send.Packet.Move();

                    // Disable send.CancellationToken.
                    send.Ctr1.Dispose();
                    send.Ctr2.Dispose();

                    // Send if not cancelled.
                    if (!send.TaskCompletion.Task.IsCompleted)
                    {
                        bool isKexInit = pkt.MessageId == MessageId.SSH_MSG_KEXINIT;

                        // If we weren't canceled by send.CancellationToken, do the send.
                        // We use abortToken instead of send.CancellationToken because
                        // we can't allow partial sends unless we're aborting the connection.
                        await connection.SendPacketAsync(pkt.Move(), abortToken).ConfigureAwait(false);

                        SemaphoreSlim? keyExchangeSemaphore = null;
                        if (isKexInit)
                        {
                            keyExchangeSemaphore = _keyReExchangeSemaphore;
                            _keyReExchangeSemaphore = null;
                        }

                        // Send completed succesfully.
                        send.TaskCompletion.SetResult(true);

                        // Don't send any more packets until Key Re-Exchange completed.
                        if (keyExchangeSemaphore != null)
                        {
                            await keyExchangeSemaphore.WaitAsync(abortToken).ConfigureAwait(false);
                            keyExchangeSemaphore.Dispose();
                        }
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
                        send.Packet.Dispose();
                        send.Ctr1.Dispose();
                        send.Ctr2.Dispose();
                        if (!send.TaskCompletion.Task.IsCompleted)
                        {
                            send.TaskCompletion.SetException(NewConnectionClosedException());
                        }
                    }
                }
            }
        }

        private async Task ReceiveLoopAsync(SshConnection connection, SshConnectionInfo ConnectionInfo)
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
                                await SendPacketAsync(clientKexInitMsg.Clone()).ConfigureAwait(false);
                            }
                            catch
                            {
                                _keyReExchangeSemaphore.Dispose();
                                _keyReExchangeSemaphore = null;
                                throw;
                            }
                            await _settings.ExchangeKeysAsync(connection, clientKexInitMsg, serverKexInitMsg: packet, _logger, _settings, ConnectionInfo, abortToken).ConfigureAwait(false);
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
                        await HandleGlobalRequestAsync(packet).ConfigureAwait(false);
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

            throw new DisconnectException(description); // TODO: pass more fields.
        }

        private void HandleDebugMessage(ReadOnlyPacket packet)
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
            string message = reader.ReadUtf8String(); // MAYDO: pass this to the user, maybe.
            reader.SkipString();
            reader.ReadEnd();
        }

        private async ValueTask HandleGlobalRequestAsync(ReadOnlyPacket packet)
        {
            // If the recipient does not recognize or support the request, it simply
            // responds with SSH_MSG_REQUEST_FAILURE.
            using var response = RentPacket();
            response.GetWriter().WriteMessageId(MessageId.SSH_MSG_REQUEST_FAILURE);
            await SendPacketAsync(response.Move()).ConfigureAwait(false);
        }

        // This method is for doing a clean shutdown which may involve sending some messages over the wire.
        // public async Task DisconnectAsync(CancellationToken cancellationToken)
        // {
        //     // SshClientSettings needs an upper bound time for this method (e.g. SshClientSettings.DisconnectTimeout)

        //     // In a finally block, this method calls Dispose.
        // }

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
                Abort(NewObjectDisposedException());
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
            throw NewConnectionClosedException();
        }

        private Exception NewConnectionClosedException()
        {
            if (_abortReason == null)
            {
                ThrowHelper.ThrowInvalidOperation("Connection not closed");
            }
            if (_abortReason == ClosedByPeer)
            {
                return new ConnectionClosedException("Connection closed by peer.");
            }
            else
            {
                return new ConnectionClosedException($"Connection closed: {_abortReason!.Message}", _abortReason);
            }
        }

        private async void OnChannelDisposed(SshClientChannelContext context)
        {
            try
            {
                if (!ConnectionClosed.IsCancellationRequested)
                {
                    await context.CloseAsync(disposing: true).ConfigureAwait(false);
                }
            }
            catch (Exception e)
            {
                Abort(e);
            }
            finally
            {
                // No more messages will be queued for the channel.
                lock (_channels)
                {
                    FreeChannel(context.LocalChannel);
                }

                context.DoDispose();
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
                ThrowHelper.ThrowInvalidOperation("Not connected.");
            }
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
        private bool HasConnected =>
            _sendQueue != null;
    }
}
