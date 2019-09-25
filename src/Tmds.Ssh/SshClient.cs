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
    delegate Task ChannelHandler(ChannelContext context);

    public sealed partial class SshClient : IAsyncDisposable
    {
        private readonly SshClientSettings _settings;
        private readonly ILogger _logger;
        private readonly object _gate = new object();
        private readonly CancellationTokenSource _abortCts;    // Used to stop all operations
        private bool _disposed;
        private Channel<PendingSend>? _sendQueue;              // Multiple senders push into the queue
        private Task ?_runningConnectionTask;                  // Task that encompasses all operations
        private Exception? _abortReason;                       // Reason why the client stopped
        private static readonly Exception ClosedByPeer = new Exception(); // Sentinel _abortReason
        private List<Task>? _connectionUsers;                  // Tasks that use the connection (like Channels)
        private int _nextChannelNumber;
        private readonly Dictionary<int, ChannelExecution> _channels = new Dictionary<int, ChannelExecution>();
        private readonly SequencePool _sequencePool = new SequencePool();
        private SemaphoreSlim? _keyReExchangeSemaphore;

        // TODO: maybe implement this using IValueTaskSource/ManualResetValueTaskSource
        struct PendingSend
        {
            public Sequence Packet;
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
            if (settings.Host == null)
            {
                throw new ArgumentNullException(nameof(settings.Host));
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
                await socket.ConnectAsync(settings.Host!, settings.Port, ct);
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
            SshConnection? sshConnection = null;
            try
            {
                // Cancel when:
                // * DisposeAsync is called (_abortCts)
                // * CancellationToken parameter from ConnectAsync (connectCt)
                // * Timeout from ConnectionSettings (ConnectTimeout)
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(connectCt, _abortCts.Token);
                connectCts.CancelAfter(_settings.ConnectTimeout);

                // Connect to the remote host
                sshConnection = await _settings.EstablishConnectionAsync(_logger, _sequencePool, _settings, connectCts.Token);

                // Setup ssh connection
                if (!_settings.NoProtocolVersionExchange)
                {
                    await _settings.ExchangeProtocolVersionAsync(sshConnection, _logger, _settings, connectCts.Token);
                }
                if (!_settings.NoKeyExchange)
                {
                    {
                        using Sequence localExchangeInitMsg = KeyExchange.CreateKeyExchangeInitMessage(_sequencePool, _logger, _settings);
                        await sshConnection.SendPacketAsync(localExchangeInitMsg.AsReadOnlySequence(), connectCts.Token);
                    }
                    {
                        using Sequence? remoteExchangeInitMsg = await sshConnection.ReceivePacketAsync(connectCts.Token);
                        await _settings.ExchangeKeysAsync(sshConnection, remoteExchangeInitMsg, _logger, _settings, connectCts.Token);
                    }
                }
                if (!_settings.NoUserAuthentication)
                {
                    await _settings.AuthenticateUserAsync(sshConnection, _logger, _settings, connectCts.Token);
                }

                // Allow sending.
                _sendQueue = Channel.CreateUnbounded<PendingSend>(new UnboundedChannelOptions
                {
                    SingleWriter = false,
                    SingleReader = true,
                    AllowSynchronousContinuations = true
                });
                // Allow connection users.
                _connectionUsers = new List<Task>();
                // ConnectAsync completed successfully.
                connectTcs.SetResult(true);
            }
            catch (Exception e)
            {
                sshConnection?.Dispose();

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

            await HandleConnectionAsync(sshConnection);
        }

        internal static async Task SetupConnectionAsync(SshConnection sshConnection, ILogger logger, SshClientSettings settings, CancellationToken token)
        {
            await Task.Delay(0);
        }

        private async Task HandleConnectionAsync(SshConnection sshConnection)
        {
            try
            {
                try
                {
                    Task sendTask = SendLoopAsync(sshConnection);
                    AddConnectionUser(sendTask);
                    AddConnectionUser(ReceiveLoopAsync(sshConnection));

                    // Wait for a task that runs as long as the connection.
                    await sendTask.ContinueWith(_ => { /* Ignore Failed/Canceled */ });
                }
                catch (Exception e) // Unexpected: the continuation doesn't throw.
                {
                    Abort(e);
                }
                finally
                {
                    Task[] connectionUsers;
                    lock (_gate)
                    {
                        connectionUsers = _connectionUsers!.ToArray();
                        // Accept no new users.
                        _connectionUsers = null;
                    }
                    // Wait for all connection users.
                    await Task.WhenAll(connectionUsers);
                }
            }
            catch (Exception e)
            {
                Abort(e); // Unlikely, Abort will be called already.
            }
            finally
            {
                sshConnection.Dispose();
            }

            async void AddConnectionUser(Task task)
            {
                lock (_gate)
                {
                    _connectionUsers!.Add(task);
                }

                try
                {
                    await task;
                    RemoveConnectionUser(task);
                }
                catch (Exception e)
                {
                    RemoveConnectionUser(task);
                    Abort(e);
                }

                void RemoveConnectionUser(Task task)
                {
                    lock (_gate)
                    {
                        List<Task> connectionUsers = _connectionUsers!;

                        if (connectionUsers != null)
                        {
                            connectionUsers.Remove(task);
                        }
                    }
                }
            }
        }

        internal async Task HandleChannelAsync(ChannelHandler handler, CancellationToken ct)
        {
            async Task runChannel()
            {
                // Yield to avoid holding _gate lock.
                await Task.Yield();

                int channelNumber;
                lock (_gate)
                {
                    channelNumber = _nextChannelNumber++; // TODO: handle numbering
                }
                try
                {
                    using var channelContext = new ChannelExecution(this, channelNumber, _abortCts.Token, ct, handler);
                    lock (_channels)
                    {
                        _channels[channelNumber] = channelContext;
                    }
                    try
                    {
                        await channelContext.ExecuteAsync();
                    }
                    catch (OperationCanceledException) when (_abortReason != null)
                    {
                        ThrowNewConnectionClosedException();
                    }
                    finally
                    {
                        // No more messages will be queued to this channel.
                        lock (_channels)
                        {
                            _channels.Remove(channelNumber);
                        }
                    }
                }
                finally
                {
                    lock (_gate)
                    {
                        // TODO: return channel number
                    }
                }
            }

            Task task;
            lock (_gate)
            {
                ThrowIfDisposed();

                List<Task>? connectionUsers = _connectionUsers;
                if (connectionUsers == null)
                {
                    if (_abortReason != null)
                    {
                        ThrowNewConnectionClosedException();
                    }
                    else
                    {
                        // Trying to add a channel before ConnectAsync completed.
                        ThrowHelper.ThrowInvalidOperation("Not connected");
                    }
                }

                task = runChannel();
                connectionUsers!.Add(task);
            }

            try
            {
                await task;
                RemoveConnectionUser(task);
            }
            catch (Exception e)
            {
                RemoveConnectionUser(task);
                bool isOce = e is OperationCanceledException;
                if (!isOce)
                {
                    Abort(e);
                }
                throw;
            }

            void RemoveConnectionUser(Task t)
            {
                lock (_gate)
                {
                    List<Task>? connectionUsers = _connectionUsers;
                    if (connectionUsers != null)
                    {
                        connectionUsers.Remove(t);
                    }
                }
            }
        }

        private ValueTask SendPacketAsync(Sequence packet, CancellationToken ct)
        {
            Channel<PendingSend>? sendQueue = _sendQueue;

            if (sendQueue == null)
            {
                // Trying to send before SendLoopAsync completed.
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

        private async Task SendLoopAsync(SshConnection sshConnection)
        {
            CancellationToken abortToken = _abortCts.Token;
            try
            {
                while (true)
                {
                    PendingSend send = await _sendQueue!.Reader.ReadAsync(abortToken); // TODO: maybe use ReadAllAsync
                    Sequence packet = send.Packet;
                    try
                    {
                        // Disable send.CancellationToken.
                        send.CancellationTokenRegistration.Dispose();
                        if (!send.TaskCompletion.Task.IsCanceled)
                        {
                            // If we weren't canceled by send.CancellationToken, do the send.
                            // We use abortToken instead of send.CancellationToken because
                            // we can't allow partial sends unless we're aborting the connection.
                            ReadOnlySequence<byte> data = packet.AsReadOnlySequence();
                            await sshConnection.SendPacketAsync(data, abortToken);

                            SemaphoreSlim? keyExchangeSemaphore = null;
                            if (data.FirstSpan[0] == MessageNumber.SSH_MSG_KEXINIT)
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
                    finally
                    {
                        packet.Dispose();
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
                        send.Packet.Dispose();
                    }
                }
            }
        }

        private async Task ReceiveLoopAsync(SshConnection sshConnection)
        {
            CancellationToken abortToken = _abortCts.Token;
            while (true)
            {
                var packet = await sshConnection.ReceivePacketAsync(abortToken, maxLength: -1 /* don't limit */);
                if (packet == null)
                {
                    Abort(ClosedByPeer);
                    break;
                }
                else
                {
                    // for now, eat everything.
                    packet.Dispose();
                }
                var data = packet.AsReadOnlySequence();
                byte msgType = data.FirstSpan[0];

                // Connection Protocol: https://tools.ietf.org/html/rfc4254.

                // Dispatch to channels:
                // lock (_channels)
                // {
                //     var channelExecution = _channels[channelNumber];
                //     channelExecution.QueueReceivedPacket(packet);
                // }
                // Handle global requests
                // ...

                switch (msgType)
                {
                    case MessageNumber.SSH_MSG_KEXINIT:
                        // Key Re-Exchange: https://tools.ietf.org/html/rfc4253#section-9.
                        try
                        {
                            // When we send SSH_MSG_KEXINIT, we can't send other packets until key exchange completes.
                            // This is implemented using _keyReExchangeSemaphore.
                            var keyExchangeSemaphore = new SemaphoreSlim(0, 1);
                            _keyReExchangeSemaphore = keyExchangeSemaphore;
                            try
                            {
                                // this will await _keyReExchangeSemaphore and set it to null.
                                Sequence keyExchangeInitMsg = KeyExchange.CreateKeyExchangeInitMessage(_sequencePool, _logger, _settings);
                                await SendPacketAsync(keyExchangeInitMsg, abortToken);
                            }
                            catch
                            {
                                _keyReExchangeSemaphore.Dispose();
                                _keyReExchangeSemaphore = null;
                                throw;
                            }
                            await _settings.ExchangeKeysAsync(sshConnection, packet, _logger, _settings, abortToken);
                            keyExchangeSemaphore.Release();
                        }
                        finally
                        {
                            packet.Dispose();
                        }
                    break;
                }
            }
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

        private Sequence RentSequence()
            => _sequencePool.RentSequence();

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
    }
}
