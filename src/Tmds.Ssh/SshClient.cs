// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

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
        private Channel<PendingSend> _sendQueue;               // Multiple senders push into the queue
        private Task _runningConnectionTask;                   // Task that encompasses all operations
        private Exception _abortReason;                        // Reason why the client stopped
        private static readonly Exception ClosedByPeer = new Exception(); // Sentinel _abortReason
        private List<Task> _connectionUsers;                   // Tasks that use the connection (like Channels)
        private int _nextChannelNumber;
        private readonly Dictionary<int, ChannelExecution> _channels = new Dictionary<int, ChannelExecution>();
        private readonly SequencePool _sequencePool = null;

        // TODO: maybe implement this using IValueTaskSource/ManualResetValueTaskSource
        struct PendingSend
        {
            public Sequence Packet;
            public TaskCompletionSource<object> TaskCompletion;
            public CancellationToken CancellationToken;
            public CancellationTokenRegistration CancellationTokenRegistration;
        }

        public SshClient(SshClientSettings settings, ILogger logger = null)
        {
            // TODO: validate settings
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _logger = logger;
            _abortCts = new CancellationTokenSource();
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
                    ThrowInvalidOperationException("Connect may be called once.");
                }

                // ConnectAsync waits for this Task.
                var connectionCompletedTcs = new TaskCompletionSource<object>();
                task = connectionCompletedTcs.Task;

                // DisposeAsync waits for this Task to complete.
                _runningConnectionTask = RunConnectionAsync(cancellationToken, connectionCompletedTcs);
            }

            await task;
        }

        internal static async Task<SshConnection> EstablishConnectionAsync(ILogger logger, SequencePool sequencePool, SshClientSettings settings, CancellationToken ct)
        {
            Socket socket = null;
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
                // Connect to the remote host
                await socket.ConnectAsync(settings.Host, settings.Port, ct);
                socket.NoDelay = true;
                return new SocketSshConnection(logger, sequencePool, socket);
            }
            catch
            {
                socket?.Dispose();
                throw;
            }
        }

        private async Task RunConnectionAsync(CancellationToken connectCt, TaskCompletionSource<object> connectTcs)
        {
            SshConnection sshConnection = null;
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

                // Authenticate the SSH connection
                await _settings.SetupConnectionAsync(sshConnection, _logger, _settings, connectCts.Token);

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
                connectTcs.SetResult(null);
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
                        connectionUsers = _connectionUsers.ToArray();
                        // Accept no new users.
                        _connectionUsers = null;
                    }
                    // Wait for all connection users.
                    await Task.WhenAll(_connectionUsers);
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
                    _connectionUsers.Add(task);
                }

                try
                {
                    await task;
                    RemoveConnectionUser(task);
                }
                catch (Exception e)
                {
                    RemoveConnectionUser(task);
                    Abort (e);
                }

                void RemoveConnectionUser(Task task)
                {
                    lock (_gate)
                    {
                        List<Task> connectionUsers = _connectionUsers;

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
            Func<Task> runChannel = async () =>
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
                    using (var channelContext = new ChannelExecution(this, channelNumber, _abortCts.Token, ct, handler))
                    {
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
                }
                finally
                {
                    lock (_gate)
                    {
                        // TODO: return channel number
                    }
                }
            };

            Task task;
            lock (_gate)
            {
                ThrowIfDisposed();

                List<Task> connectionUsers = _connectionUsers;
                if (connectionUsers == null)
                {
                    if (_abortReason != null)
                    {
                        ThrowNewConnectionClosedException();
                    }
                    else
                    {
                        // Trying to add a channel before ConnectAsync completed.
                        ThrowInvalidOperationException("Not connected");
                    }
                }

                task = runChannel();
                connectionUsers.Add(task);
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
                    List<Task> connectionUsers = _connectionUsers;
                    if (connectionUsers != null)
                    {
                        connectionUsers.Remove(t);
                    }
                }
            }
        }

        private ValueTask SendPacketAsync(Sequence packet, CancellationToken ct)
        {
            // Synchronize with SendLoopAsync stopping.
            lock (_gate)
            {
                Channel<PendingSend> sendQueue = _sendQueue;

                if (sendQueue == null)
                {
                    if (_abortReason != null)
                    {
                        // SendLoopAsync stopped.
                        return new ValueTask(Task.FromCanceled(_abortCts.Token));
                    }
                    else
                    {
                        // Trying to send before SendLoopAsync completed.
                        ThrowInvalidOperationException("Not connected");
                    }
                }

                try
                {
                    var cts = new TaskCompletionSource<object>();
                    bool written = sendQueue.Writer.TryWrite(new PendingSend
                    {
                        Packet = packet,
                        TaskCompletion = cts,
                        CancellationToken = ct,
                        CancellationTokenRegistration = ct.Register(s => ((TaskCompletionSource<object>)s).SetCanceled(), cts)
                    });
                    if (!written)
                    {
                        // Unexpected: write to an unbound queue is always successfull.
                        ThrowInvalidOperationException("Write to SendQueue failed");
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
        }

        private void ThrowInvalidOperationException(string message)
        {
            throw new InvalidOperationException(message);
        }

        private async Task SendLoopAsync(SshConnection sshConnection)
        {
            CancellationToken abortToken = _abortCts.Token;
            try
            {
                while (true)
                {
                    PendingSend send = await _sendQueue.Reader.ReadAsync(abortToken); // TODO: maybe use ReadAllAsync
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
                            await sshConnection.SendPacketAsync(packet.AsReadOnlySequence(), abortToken);
                            send.TaskCompletion.SetResult(null);
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
                lock (_gate)
                {
                    if (_sendQueue != null)
                    {
                        while (_sendQueue.Reader.TryRead(out PendingSend send))
                        {
                            send.CancellationTokenRegistration.Dispose();
                            if (!send.TaskCompletion.Task.IsCanceled)
                            {
                                send.TaskCompletion.SetCanceled();
                            }
                            send.Packet.Dispose();
                        }
                        _sendQueue = null;
                    }
                }
            }
        }

        private async Task ReceiveLoopAsync(SshConnection sshConnection)
        {
            CancellationToken abortToken = _abortCts.Token;
            while (true)
            {
                var packet = await sshConnection.ReceivePacketAsync(abortToken);
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
                // Dispatch to channels:
                // lock (_channels)
                // {
                //     var channelExecution = _channels[channelNumber];
                //     channelExecution.QueueReceivedPacket(packet);
                // }
                // Handle global requests
                // ...
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
            Task runningConnectionTask = null;
            lock (_gate)
            {
                _disposed = true;
                runningConnectionTask = _runningConnectionTask;
            }
            Abort(new ObjectDisposedException(GetType().FullName));
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
                throw new ArgumentNullException(nameof(reason));
            }

            // Capture the first exception to call Abort.
            // Once we cancel the token, we can expect more Abort calls.
            if (Interlocked.CompareExchange(ref _abortReason, reason, null) == null)
            {
                _abortCts.Cancel();
            }
        }

        private Sequence RentSequence()
        {
            throw new NotImplementedException();
        }

        private void ThrowNewConnectionClosedException()
        {
            if (_abortReason == null)
            {
                ThrowInvalidOperationException("Connection not closed");
            }
            string message;
            Exception innerException;
            if (_abortReason == ClosedByPeer)
            {
                message = "Connection closed by peer.";
                innerException = null;
            }
            else
            {
                message = $"Connection closed: {_abortReason.Message}";
                innerException = _abortReason;
            }
            throw new ConnectionClosedException(message, innerException);
        }
    }
}
