// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using static Tmds.Ssh.Interop;

namespace Tmds.Ssh
{
    public sealed class SshClient : IDisposable
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

        private SessionState _state = SessionState.Initial;
        private TaskCompletionSource<object> _connectTcs;
        private TaskCompletionSource<FlushResult> _flushedTcs;
        private SshSessionException _closeReason;

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
                _client = null;

                if (interruptPollThread)
                {
                    PollThread.InterruptPollThread();
                }
            }
        }

        public SshClient(string destination)
        {
            EnableDebugLogging();
            _clientSettings = new SshClientSettings(destination);
            _ssh = ssh_new();
            ssh_set_blocking(_ssh, blocking: 0);
            ssh_options_set(_ssh, SshOption.Host, _clientSettings.Host);
            ssh_options_set(_ssh, SshOption.User, _clientSettings.UserName);
            ssh_options_set(_ssh, SshOption.Port, (uint)_clientSettings.Port);
        }

        internal static void EnableDebugLogging()
        {
#if DEBUG
            Interop.ssh_set_log_level(1000);
#endif
        }

        public async Task ConnectAsync()
        {
            TaskCompletionSource<object> tcs;

            lock (Gate)
            {
                EnsureState(SessionState.Initial);

                tcs = _connectTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
                _state = SessionState.Connecting;

                Process();
            }

            // 'await' to include method in Exception StackTrace.
            await tcs.Task.ConfigureAwait(false);
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

        private void Disconnect(SshSessionException closeReason)
        {
            EnableDebugLogging();
            Debug.Assert(Monitor.IsEntered(Gate));

            if (_state >= SessionState.Disconnected)
            {
                return;
            }

            _state = SessionState.Disconnected;
            _closeReason = closeReason;

            _connectTcs?.SetException(GetErrorException());
            _flushedTcs?.SetResult(FlushResult.SessionDisconnected);

            if (PollSocket != null)
            {
                PollThread.RemoveSession(this); // this disposes the socket.
                PollSocket = null;
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
                            if (PollSocket == null)
                            {
                                PollThread.AddSession(this);
                                Debug.Assert(PollSocket != null);
                            }
                            if (rv == SSH_AGAIN)
                            {
                                return;
                            }
                            else
                            {
                                _state = SessionState.VerifyServer;
                            }
                        }
                        else
                        {
                            CompleteConnect(new SshSessionException(ssh_get_error(_ssh)));
                            return;
                        }
                        break;
                    case SessionState.VerifyServer:
                        KnownHostResult verifyResult = ssh_session_is_known_server(_ssh);
                        if (verifyResult == KnownHostResult.Ok)
                        {
                            _state = SessionState.Authenticate;
                        }
                        else
                        {
                            CompleteConnect(new SshSessionException("Server not trusted."));
                            return;
                        }
                        break;
                    case SessionState.Authenticate:
                        AuthResult authResult = ssh_userauth_publickey_auto(_ssh, null, null);
                        if (authResult == AuthResult.Again)
                        {
                            return;
                        }
                        else if (authResult == AuthResult.Success)
                        {
                            _state = SessionState.Connected;
                            var tcs = _connectTcs;
                            _connectTcs = null;
                            tcs.SetResult(null);
                        }
                        else
                        {
                            CompleteConnect(new SshSessionException("Client authentication failed."));
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
                    Disconnect((SshSessionException)exception);
                }
                return exception;
            }
        }

        private void CompleteConnect(SshSessionException exception)
        {
            var tcs = _connectTcs;
            _connectTcs = null;
            if (exception == null)
            {
                tcs.SetResult(null);
            }
            else
            {
                Disconnect(exception);
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
            SshChannel channel;
            Task openTask;
            using (GateWithPollCheck())
            {
                EnsureState(SessionState.Connected);

                cancellationToken.ThrowIfCancellationRequested();

                channel = new SshChannel(this, options);
                _channels.Add(channel);

                openTask = channel.OpenAsync();
            }

            using var _ = cancellationToken.Register(o => ((SshChannel)o).Cancel(), channel);

            await openTask.ConfigureAwait(false);

            return channel;
        }

        internal Socket PollSocket { get; private set; }

        internal Socket CreatePollSocket()
        {
            Debug.Assert(PollSocket == null);
            return PollSocket = new Socket(new SafeSocketHandle(new IntPtr(ssh_get_fd(_ssh)), ownsHandle: false));
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

                Task<FlushResult> flushed = null;
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