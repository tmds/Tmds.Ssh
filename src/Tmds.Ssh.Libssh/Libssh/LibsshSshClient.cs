// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using static Tmds.Ssh.Libssh.Interop;

namespace Tmds.Ssh.Libssh;

sealed partial class LibsshSshClient : ISshClientImplementation
{
    enum SessionState
    {
        Initial,

        // ConnectAsync steps
        Connecting,
        ConnectingComplete,
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

    private static readonly Exception DisposedException = NewObjectDisposedException();

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
        private LibsshSshClient _client;

        internal _GateWithPollCheck(LibsshSshClient client)
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

    public LibsshSshClient(SshClientSettings clientSettings)
    {
        _clientSettings = clientSettings ?? throw new ArgumentNullException(nameof(clientSettings));

        EnableDebugLogging();

        _ssh = ssh_new();
        ssh_set_blocking(_ssh, blocking: 0);
        ssh_options_set(_ssh, SshOption.Host, _clientSettings.Host);
        ssh_options_set(_ssh, SshOption.User, _clientSettings.UserName);
        ssh_options_set(_ssh, SshOption.Port, (uint)_clientSettings.Port);

        string invalidFilePath = Platform.IsWindows ? "C:\\" : "/";
        if (!_clientSettings.CheckGlobalKnownHostsFile)
        {
            ssh_options_set(_ssh, SshOption.GlobalKnownHosts, invalidFilePath);
        }
        if (string.IsNullOrEmpty(_clientSettings.KnownHostsFilePath))
        {
            ssh_options_set(_ssh, SshOption.KnownHosts, invalidFilePath);
        }
        else
        {
            ssh_options_set(_ssh, SshOption.KnownHosts, _clientSettings.KnownHostsFilePath);
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
            // SessionState.Connecting
            // calling ssh_connect until it completes.
            await SshConnectAsync(cancellationToken).ConfigureAwait(false);

            // SessionState.VerifyServer
            // ssh_connect completed, now verify the server key.
            await VerifyServerAsync(cancellationToken).ConfigureAwait(false);

            // SessionState.Authenticate
            // server trusted, now authenticate.
            await AuthenticateAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            lock (Gate)
            {
                Disconnect(e);
            }

            throw;
        }
    }

    private async Task SshConnectAsync(CancellationToken cancellationToken)
    {
        TaskCompletionSource<object?> tcs;
        lock (Gate)
        {
            if (_state != SessionState.Initial)
            {
                throw new InvalidOperationException($"Unable to perform operation, session is {_state}.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            tcs = _connectTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _state = SessionState.Connecting;
            Connect();
        }
        {
            TimerCallback timerCallback =
                static o => AbortConnect((LibsshSshClient)o!, new SshConnectionException("The operation has timed out.", new TimeoutException()));
            using var timer = new Timer(timerCallback, this, dueTime: (int)_clientSettings.ConnectTimeout.TotalMilliseconds, period: -1);
            using CancellationTokenRegistration ctr = RegisterConnectCancellation(this, cancellationToken);
            await tcs.Task.ConfigureAwait(false); // await so the timer doesn't dispose.
        }
    }

    private async ValueTask VerifyServerAsync(CancellationToken cancellationToken)
    {
        KeyVerificationResult result = KeyVerificationResult.Unknown;
        lock (Gate)
        {
            if (_state != SessionState.ConnectingComplete)
            {
                throw GetErrorException();
            }
            _state = SessionState.VerifyServer;

            bool checkKnownHosts = _clientSettings.CheckGlobalKnownHostsFile ||
                                    !string.IsNullOrEmpty(_clientSettings.KnownHostsFilePath);
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

            using SshKeyHandle? key = ssh_get_server_publickey(_ssh);
            if (key == null)
            {
                throw GetErrorException();
            }
            int rv = ssh_get_publickey_hash(key!, Interop.PublicKeyHashType.SSH_PUBLICKEY_HASH_SHA256, out byte[] hash);
            if (rv != SSH_OK)
            {
                throw new SshConnectionException("Could not obtain public key.");
            }
            string sha256FingerPrint = Convert.ToBase64String(hash).TrimEnd('=');
            _connectionInfo.ServerKey = new SshKey(sha256FingerPrint);
        }

        if (result != KeyVerificationResult.Trusted)
        {
            if (_clientSettings.KeyVerification != null &&
                (result == KeyVerificationResult.Changed || result == KeyVerificationResult.Unknown))
            {
                try
                {
                    result = await _clientSettings.KeyVerification(result, _connectionInfo, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception e) when (e is not SshConnectionException && e is not OperationCanceledException)
                {
                    // Wrap the exception
                    throw new SshConnectionException($"Key verification failed: {e.Message}.", e);
                }

                if (result == KeyVerificationResult.AddKnownHost)
                {
                    lock (Gate)
                    {
                        if (_state != SessionState.VerifyServer)
                        {
                            throw GetErrorException();
                        }
                        if (!string.IsNullOrEmpty(_clientSettings.KnownHostsFilePath))
                        {
                            if (ssh_session_update_known_hosts(_ssh) != SSH_OK)
                            {
                                throw GetErrorException();
                            }
                        }
                    }
                    result = KeyVerificationResult.Trusted;
                }
            }
        }
        if (result != KeyVerificationResult.Trusted)
        {
            throw new SshConnectionException("Server not trusted.");
        }
    }

    private Task AuthenticateAsync(CancellationToken cancellationToken)
    {
        TaskCompletionSource<object?> tcs;
        lock (Gate)
        {
            if (_state != SessionState.VerifyServer)
            {
                throw GetErrorException();
            }

            tcs = _connectTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _state = SessionState.Authenticate;
            Authenticate();
        }
        {
            using CancellationTokenRegistration ctr = RegisterConnectCancellation(this, cancellationToken);
            return tcs.Task;
        }
    }

    static CancellationTokenRegistration RegisterConnectCancellation(LibsshSshClient client, CancellationToken cancellationToken)
    {
        if (cancellationToken.CanBeCanceled)
        {
            return cancellationToken.Register(
                static o =>
                {
                    var arg = ((LibsshSshClient client, CancellationToken ct))o!;
                    AbortConnect(arg.client, new OperationCanceledException(arg.ct));
                }, (client, cancellationToken));
        }
        return default;
    }

    static void AbortConnect(LibsshSshClient sshClient, Exception e)
    {
        lock (sshClient.Gate)
        {
            if (sshClient._connectTcs != null)
            {
                sshClient.CompleteConnectStep(e);
            }
        }
    }

    private void EnsureConnected()
    {
        if (_state != SessionState.Connected)
        {
            ThrowNotConnectedState();
        }
    }

    public void Dispose()
    {
        lock (Gate)
        {
            Disconnect(DisposedException);
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
        _closeReason ??= closeReason;

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

    internal void HandleEvents()
    {
        Debug.Assert(Monitor.IsEntered(Gate));

        switch (_state)
        {
            case SessionState.Connecting:
                Connect();
                break;
            case SessionState.ConnectingComplete:
                break;
            case SessionState.VerifyServer:
                break;
            case SessionState.Authenticate:
                Authenticate();
                break;
            case SessionState.Connected:
                HandleEventsWhenConnected();
                break;
            case SessionState.Disconnected:
            case SessionState.Disposed:
                break;
            default:
                throw new IndexOutOfRangeException($"Invalid Session state: {_state}.");
        }
    }

    private void HandleEventsWhenConnected()
    {
        Debug.Assert(Monitor.IsEntered(Gate));

        if ((ssh_get_status(_ssh) & StatusFlags.ClosedError) != 0)
        {
            Disconnect(GetErrorException());
            return;
        }
        else if (!ssh_is_connected(_ssh))
        {
            Disconnect(new SshConnectionException("Connection closed."));
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
    }

    private void Connect()
    {
        Debug.Assert(Monitor.IsEntered(Gate));

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
                _state = SessionState.ConnectingComplete;
                CompleteConnectStep(null);
            }
        }
        else
        {
            CompleteConnectStep(new SshConnectionException(ssh_get_error(_ssh)));
        }
    }

    internal SshException CreateCloseExceptionGated()
    {
        lock (Gate)
        {
            return GetErrorException();
        }
    }

    internal SshException GetErrorException()
    {
        Debug.Assert(Monitor.IsEntered(Gate));

        if (_state >= SessionState.Disconnected)
        {
            Exception? closeReason = _closeReason;
            if (closeReason is null)
            {
                return new SshConnectionClosedException(SshConnectionClosedException.ConnectionClosedByPeer);
            }
            else if (closeReason == DisposedException)
            {
                return new SshConnectionClosedException(SshConnectionClosedException.ConnectionClosedByDispose, DisposedException);
            }
            else
            {
                return new SshConnectionClosedException(SshConnectionClosedException.ConnectionClosedByAbort, closeReason);
            }
        }
        else
        {
            string message = ssh_get_error(SshHandle);
            bool isFatal = ssh_get_error_is_fatal(SshHandle);
            SshException exception = isFatal ? new SshConnectionException(message) : new SshChannelException(message);
            if (isFatal)
            {
                Disconnect(exception);
            }
            return exception;
        }
    }

    private void CompleteConnectStep(Exception? exception)
    {
        Debug.Assert(Monitor.IsEntered(Gate));
        Debug.Assert(_connectTcs != null);

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

    private void ThrowNotConnectedState()
    {
        Debug.Assert(Monitor.IsEntered(Gate));
        Debug.Assert(_state != SessionState.Connected);

        if (_state == SessionState.Disposed)
        {
            throw NewObjectDisposedException();
        }
        else if (_state >= SessionState.Disconnected)
        {
            throw GetErrorException();
        }
        else
        {
            throw new InvalidOperationException($"Unable to perform operation, session is {_state}.");
        }
    }

    public Task<ISshChannel> OpenRemoteProcessChannelAsync(Type channelType, string command, CancellationToken cancellationToken = default)
        => OpenChannelAsync(channelType, new SshChannelOptions(SshChannelType.Execute) { Command = command }, cancellationToken);

    public Task<ISshChannel> OpenTcpConnectionChannelAsync(Type channelType, string host, int port, CancellationToken cancellationToken = default)
        => OpenChannelAsync(channelType, new SshChannelOptions(SshChannelType.TcpStream) { Host = host, Port = port }, cancellationToken);

    public Task<ISshChannel> OpenUnixConnectionChannelAsync(Type channelType, string path, CancellationToken cancellationToken = default)
        => OpenChannelAsync(channelType, new SshChannelOptions(SshChannelType.UnixStream) { Path = path }, cancellationToken);

    public Task<ISshChannel> OpenSftpClientChannelAsync(Type channelType, CancellationToken cancellationToken = default)
        => OpenChannelAsync(channelType, new SshChannelOptions(SshChannelType.Sftp), cancellationToken);

    private async Task<ISshChannel> OpenChannelAsync(Type channelType, SshChannelOptions options, CancellationToken cancellationToken)
    {
        SshChannel? channel = null;
        try
        {
            Task openTask;
            using (GateWithPollCheck())
            {
                EnsureConnected();

                cancellationToken.ThrowIfCancellationRequested();

                channel = new SshChannel(this, options, channelType);
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
        return _pollSocket = new Socket(new SafeSocketHandle(ssh_get_fd(_ssh), ownsHandle: false));
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
                throw CreateCloseExceptionGated();
            }
        }
    }

    private static Exception NewObjectDisposedException()
    {
        return new ObjectDisposedException(typeof(SshClient).FullName);
    }
}
