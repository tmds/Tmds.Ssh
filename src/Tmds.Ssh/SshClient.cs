// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using static Tmds.Ssh.Interop;

namespace Tmds.Ssh
{
    public sealed partial class SshClient : IDisposable
    {
        enum SessionState
        {
            Initial,

            // ConnectAsync steps
            Connecting,
            VerifyServer,
            Authenticate,

            Connected,

            Disconnected,
            Disposed
        }

        enum FlushResult
        {
            Flushed,
            MaybeCancelled,
            SessionDisconnected
        }

        private readonly object _gate = new();
        private readonly List<SshChannel> _channels = new();
        private readonly SessionHandle _ssh;
        private readonly SshClientSettings _clientSettings;
        private readonly AuthState _authState = new AuthState();
        private readonly SshConnectionInfo _connectionInfo = new SshConnectionInfo();

        private SessionState _state = SessionState.Initial;
        private TaskCompletionSource<object?>? _connectTcs;
        private TaskCompletionSource<FlushResult>? _flushedTcs;
        private Exception? _closeReason;
        private Socket? _pollSocket;

        internal SessionHandle SshHandle => _ssh;
        internal object Gate => _gate;
        internal _GateWithPollCheck GateWithPollCheck()
            => new _GateWithPollCheck(this);

        internal struct _GateWithPollCheck : IDisposable
        {
            private SshClient _client;

            internal _GateWithPollCheck(SshClient client)
            {
                _client = client;
                Monitor.Enter(client.Gate);
            }

            public void Dispose()
            {
                // Ensure PollThread polls for SessionPollFlags.
                bool interruptPollThread = false;
                PollFlags sessionPollFlags = _client.SessionPollFlags;
                PollFlags pollThreadPollFlags = _client.PollThreadPollFlags;
                if ((sessionPollFlags & ~pollThreadPollFlags) != 0)
                {
                    _client.PollThreadPollFlags = sessionPollFlags | pollThreadPollFlags;
                    interruptPollThread = true;
                }

                Monitor.Exit(_client.Gate);
                _client = null!;

                if (interruptPollThread)
                {
                    PollThread.InterruptPollThread();
                }
            }
        }

        public SshClient(string destination, Action<SshClientSettings>? configure = null)
        {
            EnableDebugLogging();

            _clientSettings = new SshClientSettings(destination);
            configure?.Invoke(_clientSettings);

            _ssh = ssh_new();
            ssh_set_blocking(_ssh, blocking: 0);
            ssh_options_set(_ssh, SshOption.Host, _clientSettings.Host);
            ssh_options_set(_ssh, SshOption.User, _clientSettings.UserName);
            ssh_options_set(_ssh, SshOption.Port, (uint)_clientSettings.Port);

            string invalidFilePath = Platform.IsWindows ? "C:\\" : "/";
            if (!_clientSettings.CheckGlobalKnownHostFile)
            {
                ssh_options_set(_ssh, SshOption.GlobalKnownHosts, invalidFilePath);
            }
            if (string.IsNullOrEmpty(_clientSettings.KnownHostFile))
            {
                ssh_options_set(_ssh, SshOption.KnownHosts, invalidFilePath);
            }
            else
            {
                ssh_options_set(_ssh, SshOption.KnownHosts, _clientSettings.KnownHostFile);
            }

            _connectionInfo.Host = _clientSettings.Host;
            _connectionInfo.Port = _clientSettings.Port;
        }

        internal static void EnableDebugLogging()
        {
#if DEBUG
            Interop.ssh_set_log_level(1000);
#endif
        }

        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                TaskCompletionSource<object?> tcs;
                // SessionState.Connecting
                lock (Gate)
                {
                    EnsureState(SessionState.Initial);

                    cancellationToken.ThrowIfCancellationRequested();

                    tcs = _connectTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    _state = SessionState.Connecting;

                    Process();
                }
                {
                    TimerCallback timerCallback =
                        static o => AbortConnect((SshClient)o!, new SshSessionException("The operation has timed out.", new TimeoutException()));
                    using var timer = new Timer(timerCallback, this, dueTime: (int)_clientSettings.ConnectTimeout.TotalMilliseconds, period: -1);
                    using CancellationTokenRegistration ctr = RegisterCancellation(this, cancellationToken);
                    await tcs.Task.ConfigureAwait(false);
                }

                // SessionState.VerifyServer
                KeyVerificationResult result = KeyVerificationResult.Unknown;
                lock (Gate)
                {
                    if (_state != SessionState.VerifyServer)
                    {
                        throw GetErrorException();
                    }

                    bool checkKnownHosts = _clientSettings.CheckGlobalKnownHostFile ||
                                            !string.IsNullOrEmpty(_clientSettings.KnownHostFile);
                    if (checkKnownHosts)
                    {
                        result = ssh_session_is_known_server(_ssh) switch
                        {
                            KnownHostResult.Error => KeyVerificationResult.Error,
                            KnownHostResult.Ok => KeyVerificationResult.Trusted,
                            KnownHostResult.FileNotFound => KeyVerificationResult.Unknown,
                            KnownHostResult.Unknown => KeyVerificationResult.Unknown,
                            KnownHostResult.Changed => KeyVerificationResult.Changed,
                            KnownHostResult.OtherType => KeyVerificationResult.Error,
                            _ => throw new IndexOutOfRangeException($"Unknown KnownHostResult"),
                        };
                    }

                    int rv = ssh_get_server_publickey(_ssh, out SshKeyHandle key);
                    if (rv == SSH_ERROR)
                    {
                        throw GetErrorException();
                    }
                    rv = ssh_get_publickey_hash(key, Interop.PublicKeyHashType.SSH_PUBLICKEY_HASH_SHA256, out byte[] hash);
                    key.Dispose();
                    if (rv != SSH_OK)
                    {
                        throw new SshSessionException("Could not obtain public key.");
                    }
                    _connectionInfo.ServerKey = new PublicKey(hash);
                }

                if (result != KeyVerificationResult.Trusted)
                {
                    if (_clientSettings.KeyVerification != null &&
                        (result == KeyVerificationResult.Changed || result == KeyVerificationResult.Unknown))
                    {
                        try
                        {
                            result = await _clientSettings.KeyVerification(result, _connectionInfo, cancellationToken);
                        }
                        catch (Exception e) when (e is not SshSessionException)
                        {
                            // Wrap the exception
                            throw new SshSessionException($"Key verification failed: {e.Message}.", e);
                        }
                    }
                }
                if (result == KeyVerificationResult.AddKnownHost)
                {
                    throw new NotImplementedException(); // TODO: add key
                    result = KeyVerificationResult.Trusted;
                }
                if (result != KeyVerificationResult.Trusted)
                {
                    throw new SshSessionException("Server not trusted.");
                }

                // SessionState.Authenticate
                lock (Gate)
                {
                    if (_state != SessionState.VerifyServer)
                    {
                        throw GetErrorException();
                    }

                    tcs = _connectTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    _state = SessionState.Authenticate;

                    Process();
                }
                {
                    using CancellationTokenRegistration ctr = RegisterCancellation(this, cancellationToken);
                    await tcs.Task.ConfigureAwait(false);
                }
            }
            catch (Exception e)
            {
                lock (Gate)
                {
                    Disconnect(e);
                }

                throw;
            }

            static CancellationTokenRegistration RegisterCancellation(SshClient client, CancellationToken cancellationToken)
            {
                if (cancellationToken.CanBeCanceled)
                {
                    return cancellationToken.Register(
                        static o =>
                        {
                            var arg = ((SshClient client, CancellationToken ct))o!;
                            AbortConnect(arg.client, new OperationCanceledException(arg.ct));
                        }, (client, cancellationToken));
                }
                return default;
            }
        }

        static void AbortConnect(SshClient sshClient, Exception e)
        {
            lock (sshClient.Gate)
            {
                if (sshClient._connectTcs != null)
                {
                    sshClient.CompleteConnectStep(e);
                }
            }
        }

        private void EnsureState(SessionState state)
        {
            if (_state != state)
            {
                ThrowInvalidState(state);
            }
        }

        internal void EnsureConnected()
            => EnsureState(SessionState.Connected);

        public void Dispose()
        {
            lock (Gate)
            {
                Disconnect(closeReason: null);
                _state = SessionState.Disposed;
            }
        }

        private void Disconnect(Exception? closeReason)
        {
            EnableDebugLogging();
            Debug.Assert(Monitor.IsEntered(Gate));

            if (_state >= SessionState.Disconnected)
            {
                return;
            }

            _state = SessionState.Disconnected;
            _closeReason = closeReason;

            _authState.Reset();

            _connectTcs?.SetException(GetErrorException());
            _flushedTcs?.SetResult(FlushResult.SessionDisconnected);

            if (_pollSocket != null)
            {
                PollThread.RemoveSession(_pollSocket);
                _pollSocket.Dispose();
                _pollSocket = null;
            }

            int countRemaining;
            while ((countRemaining = _channels.Count) > 0)
            {
                _channels[0].OnSessionDisconnect();
                Debug.Assert(_channels.Count != countRemaining);
            }

            _ssh.Dispose();
        }

        internal void RemoveChannel(SshChannel channel)
        {
            Debug.Assert(Monitor.IsEntered(Gate));

            _channels.Remove(channel);
        }

        internal void Process()
        {
            Debug.Assert(Monitor.IsEntered(Gate));

            while (true)
            {
                switch (_state)
                {
                    case SessionState.Connecting:
                        int rv = ssh_connect(_ssh);
                        if (rv == SSH_AGAIN || rv == SSH_OK)
                        {
                            if (_pollSocket == null)
                            {
                                Socket pollSocket = CreatePollSocket();
                                PollThread.AddSession(pollSocket, this);
                            }
                            if (rv != SSH_AGAIN)
                            {
                                _state = SessionState.VerifyServer;
                                CompleteConnectStep(null);
                            }
                        }
                        else
                        {
                            CompleteConnectStep(new SshSessionException(ssh_get_error(_ssh)));
                        }
                        return;
                    case SessionState.VerifyServer:
                        return;
                    case SessionState.Authenticate:
                        Authenticate();
                        if (_state != SessionState.Connected)
                        {
                            return;
                        }
                        break;
                    case SessionState.Connected:
                        if (!ssh_is_connected(_ssh))
                        {
                            Disconnect(new SshSessionException("Closed by peer."));
                            return;
                        }
                        if (_flushedTcs != null)
                        {
                            if ((SessionPollFlags & PollFlags.WritePending) == 0)
                            {
                                var tcs = _flushedTcs;
                                _flushedTcs = null;
                                tcs.SetResult(FlushResult.Flushed);
                            }
                        }
                        foreach (var channel in _channels)
                        {
                            channel.Process();
                        }
                        return;
                    case SessionState.Disconnected:
                    case SessionState.Disposed:
                        return;
                    default:
                        throw new IndexOutOfRangeException($"Invalid Session state: {_state}.");
                }
            }
        }

        internal SshException GetErrorException()
        {
            Debug.Assert(Monitor.IsEntered(Gate));

            if (_state >= SessionState.Disconnected)
            {
                return new SshSessionClosedException(_closeReason);
            }
            else
            {
                string message = ssh_get_error(SshHandle);
                bool isFatal = ssh_get_error_is_fatal(SshHandle);
                SshException exception = isFatal ? new SshSessionException(message) : new SshOperationException(message);
                if (isFatal)
                {
                    Disconnect(exception);
                }
                return exception;
            }
        }

        private void CompleteConnectStep(Exception? exception)
        {
            Debug.Assert(_connectTcs != null);
            var tcs = _connectTcs;
            _connectTcs = null;
            if (exception == null)
            {
                tcs.SetResult(null);
            }
            else
            {
                tcs.SetException(exception);
            }
        }

        private void ThrowInvalidState(SessionState desired)
        {
            if (_state == SessionState.Disposed)
            {
                throw new ObjectDisposedException(typeof(SshClient).FullName);
            }
            else if (desired == SessionState.Connected && _state >= SessionState.Disconnected)
            {
                throw GetErrorException();
            }
            else
            {
                throw new InvalidOperationException($"Unable to perform operation, session is {_state}.");
            }
        }

        public async Task<SshChannel> OpenChannelAsync(SshChannelOptions options, CancellationToken cancellationToken = default)
        {
            SshChannel? channel = null;
            try
            {
                Task openTask;
                using (GateWithPollCheck())
                {
                    EnsureState(SessionState.Connected);

                    cancellationToken.ThrowIfCancellationRequested();

                    channel = new SshChannel(this, options);
                    _channels.Add(channel);

                    openTask = channel.OpenAsync();
                }

                using var _ = cancellationToken.Register(o => ((SshChannel)o!).Cancel(), channel);

                await openTask.ConfigureAwait(false);

                return channel;
            }
            catch
            {
                channel?.Dispose();

                throw;
            }
        }

        internal Socket CreatePollSocket()
        {
            Debug.Assert(_pollSocket == null);
            return _pollSocket = new Socket(new SafeSocketHandle(new IntPtr(ssh_get_fd(_ssh)), ownsHandle: false));
        }

        internal PollFlags SessionPollFlags
        {
            get
            {
                Debug.Assert(Monitor.IsEntered(Gate));

                if (_state >= SessionState.Disconnected)
                {
                    return PollFlags.None;
                }

                return ssh_get_poll_flags(_ssh);
            }
        }

        internal PollFlags PollThreadPollFlags { get; set; }

        internal async ValueTask FlushAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                EnableDebugLogging();

                Task<FlushResult>? flushed = null;
                using (GateWithPollCheck())
                {
                    EnsureConnected();

                    cancellationToken.ThrowIfCancellationRequested();

                    if (_flushedTcs == null)
                    {
                        // TODO (libssh): SessionPollFlags doesn't reflect everything is flushed.
                        // TODO (libssh): does non-blocking ssh_blocking_flush ever poll?
                        int rv = ssh_blocking_flush(_ssh, 0);
                        if (rv == SSH_OK)
                        {
                            return;
                        }
                        else if (rv == SSH_ERROR)
                        {
                            throw GetErrorException();
                        }
                        else if (rv != SSH_AGAIN)
                        {
                            throw new IndexOutOfRangeException($"Unexpected ssh_blocking_flush return value: {rv}");
                        }
                        _flushedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    }
                    flushed = _flushedTcs.Task;
                }
                FlushResult flushResult = await flushed.ConfigureAwait(false);
                if (flushResult == FlushResult.Flushed)
                {
                    return;
                }
                else if (flushResult == FlushResult.SessionDisconnected)
                {
                    // Different callers of FlushAsync can share the
                    // Task, but they need an Exception of their own.
                    throw GetErrorException();
                }
            }
        }
    }
}