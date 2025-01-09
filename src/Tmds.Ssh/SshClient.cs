// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

public sealed partial class SshClient : IDisposable
{
    internal static readonly SftpClientOptions DefaultSftpClientOptions = new();

    private SshSession? _session;
    private Task<SshSession>? _connectingTask;
    private readonly bool _autoConnect;
    private readonly bool _autoReconnect;
    private readonly TimeSpan _connectTimeout;
    private readonly SshClientSettings? _settings;
    private readonly string? _destination;
    private readonly SshConfigSettings? _sshConfigOptions;
    private readonly SshLoggers _loggers;
    private readonly Lock _gate = new();
    private State _state = State.Initial;

    enum State
    {
        Initial,
        Connecting,
        Connected,
        Disconnected,
        Disposed
    }

    // For testing.
    internal bool IsDisposed => _state == State.Disposed;

    public SshClient(string destination, ILoggerFactory? loggerFactory = null) :
        this(destination, SshConfigSettings.NoConfig, loggerFactory)
    { }

    public SshClient(SshClientSettings settings, ILoggerFactory? loggerFactory = null) :
        this(settings, destination: null, configSettings: null,
             settings?.AutoConnect ?? default, settings?.AutoReconnect ?? default, settings?.ConnectTimeout ?? default,
             loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(settings);
    }

    public SshClient(string destination, SshConfigSettings sshConfigOptions, ILoggerFactory? loggerFactory = null) :
        this(settings: null, destination, sshConfigOptions,
             sshConfigOptions?.AutoConnect ?? default, sshConfigOptions?.AutoReconnect ?? default, sshConfigOptions?.ConnectTimeout ?? default,
             loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(sshConfigOptions);
    }

    private SshClient(
        SshClientSettings? settings,
        string? destination,
        SshConfigSettings? configSettings,
        bool autoConnect,
        bool autoReconnect,
        TimeSpan connectTimeout,
        ILoggerFactory? loggerFactory)
    {
        settings?.Validate();
        configSettings?.Validate();

        _settings = settings;
        _destination = destination;
        _sshConfigOptions = configSettings;
        _autoConnect = autoConnect;
        _autoReconnect = autoReconnect;
        _connectTimeout = connectTimeout;
        _loggers = new SshLoggers(loggerFactory);
    }

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        State state = _state;
        if (state != State.Initial && state != State.Disposed)
        {
            throw new InvalidOperationException($"{nameof(ConnectAsync)} may only be called once.");
        }
        await GetSessionAsync(cancellationToken, explicitConnect: true).ConfigureAwait(false);
    }

    public CancellationToken Disconnected
    {
        get
        {
            SshSession session = GetConnectedSesion();
            return session.ConnectionClosed;
        }
    }

    private SshSession GetConnectedSesion([CallerMemberNameAttribute]string? callerMethod = null)
    {
        if (_autoReconnect)
        {
            // Don't allow with reconnect because reconnecting means a new session
            // may be automatically established, while we want to return a session that applies to all operations
            // performed against the client.
            throw new InvalidOperationException($"{callerMethod} can not be used when {nameof(_settings.AutoReconnect)} is set.");
        }
        lock (_gate)
        {
            State state = _state;
            switch (state)
            {
                case State.Initial:
                case State.Connecting:
                    throw new InvalidOperationException($"{callerMethod} can only be called after a connection is established.");
                case State.Disposed:
                    throw NewObjectDisposedException();
                default:
                    return _session!;
            }
        }
    }

    internal async Task ConnectAsync(ConnectCallback connect, ConnectContext context, CancellationToken cancellationToken = default)
        => await GetSessionAsync(cancellationToken, explicitConnect: true, connect, context);

    private ValueTask<SshSession> GetSessionAsync(CancellationToken cancellationToken, bool explicitConnect = false, ConnectCallback? connect = null, ConnectContext? context = null)
    {
        lock (_gate)
        {
            State state = _state;

            if (state == State.Connected ||
                (state == State.Disconnected && !_autoReconnect))
            {
                return new ValueTask<SshSession>(_session!);
            }

            return ConnectCore(state, cancellationToken, explicitConnect);
        }

        ValueTask<SshSession> ConnectCore(State state, CancellationToken cancellationToken, bool explicitConnect)
        {
            Debug.Assert(_gate.IsHeldByCurrentThread);

            if (state == State.Disposed)
            {
                throw NewObjectDisposedException();
            }

            if (!explicitConnect && !_autoConnect && (state == State.Initial || state == State.Connecting))
            {
                throw new InvalidOperationException($"{nameof(ConnectAsync)} must be called and awaited.");
            }

            Debug.Assert(connect is null || (explicitConnect && state != State.Connecting));

            if (state != State.Connecting)
            {
                _state = State.Connecting;

                if (explicitConnect)
                {
                    _connectingTask = DoConnectAsync(connect, context, cancellationToken);
                    return new ValueTask<SshSession>(_connectingTask);
                }
                else
                {
                    _connectingTask = DoConnectAsync(null, null, default);
                    return new ValueTask<SshSession>(_connectingTask.WaitAsync(cancellationToken));
                }
            }
            else
            {
                Debug.Assert(_connectingTask is not null);
                Debug.Assert(_session is not null);
                Debug.Assert(explicitConnect == false);

                return WaitForConnectCompletion(_session, _connectingTask, cancellationToken);
            }
        }

        static async ValueTask<SshSession> WaitForConnectCompletion(SshSession session, Task<SshSession> connectingTask, CancellationToken cancellationToken)
        {
            // Don't throw for disconnect exceptions (except for cancellation)
            // We return the session and the let the call on the session throw.
            await ((Task)connectingTask).WaitAsync(cancellationToken).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            cancellationToken.ThrowIfCancellationRequested();
            return session;
        }
    }

    internal void OnSessionDisconnect(SshSession session)
    {
        lock (_gate)
        {
            if (_session == session && (_state == State.Connecting || _state == State.Connected))
            {
                _state = State.Disconnected;
            }
        }
    }

    private async Task<SshSession> DoConnectAsync(ConnectCallback? connect, ConnectContext? context, CancellationToken cancellationToken)
    {
        Debug.Assert(_gate.IsHeldByCurrentThread);
        Debug.Assert(_state == State.Connecting);

        SshSession session = new SshSession(_settings, _destination, _sshConfigOptions, this, _loggers);
        _session = session;

        bool success = false;
        try
        {
            await session.ConnectAsync(connect, context, _connectTimeout, cancellationToken);
            success = true;
            return session;
        }
        finally
        {
            lock (_gate)
            {
                if (_state == State.Connecting && _session == session)
                {
                    _state = success ? State.Connected : State.Disconnected;
                }
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_state == State.Disposed)
            {
                return;
            }
            _state = State.Disposed;
        }
        _session?.Dispose();
    }

    public Task<RemoteProcess> ExecuteAsync(string command, CancellationToken cancellationToken)
        => ExecuteAsync(command, null, cancellationToken);

    public async Task<RemoteProcess> ExecuteAsync(string command, ExecuteOptions? options = null, CancellationToken cancellationToken = default)
    {
        SshSession session = await GetSessionAsync(cancellationToken).ConfigureAwait(false);
        var channel = await session.OpenRemoteProcessChannelAsync(typeof(RemoteProcess), command, cancellationToken).ConfigureAwait(false);

        Encoding standardInputEncoding = options?.StandardInputEncoding ?? ExecuteOptions.DefaultEncoding;
        Encoding standardErrorEncoding = options?.StandardErrorEncoding ?? ExecuteOptions.DefaultEncoding;
        Encoding standardOutputEncoding = options?.StandardOutputEncoding ?? ExecuteOptions.DefaultEncoding;
        return new RemoteProcess(channel,
            standardInputEncoding,
            standardErrorEncoding,
            standardOutputEncoding);
    }

    public Task<RemoteProcess> ExecuteSubsystemAsync(string subsystem, CancellationToken cancellationToken)
        => ExecuteSubsystemAsync(subsystem, null, cancellationToken);

    public async Task<RemoteProcess> ExecuteSubsystemAsync(string subsystem, ExecuteOptions? options = null, CancellationToken cancellationToken = default)
    {
        SshSession session = await GetSessionAsync(cancellationToken).ConfigureAwait(false);
        var channel = await session.OpenRemoteSubsystemChannelAsync(typeof(RemoteProcess), subsystem, cancellationToken).ConfigureAwait(false);

        Encoding standardInputEncoding = options?.StandardInputEncoding ?? ExecuteOptions.DefaultEncoding;
        Encoding standardErrorEncoding = options?.StandardErrorEncoding ?? ExecuteOptions.DefaultEncoding;
        Encoding standardOutputEncoding = options?.StandardOutputEncoding ?? ExecuteOptions.DefaultEncoding;
        return new RemoteProcess(channel,
            standardInputEncoding,
            standardErrorEncoding,
            standardOutputEncoding);
    }

    public async Task<SshDataStream> OpenTcpConnectionAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        SshSession session = await GetSessionAsync(cancellationToken).ConfigureAwait(false);
        return await session.OpenTcpConnectionChannelAsync(host, port, cancellationToken).ConfigureAwait(false);
    }

    public async Task<SshDataStream> OpenUnixConnectionAsync(string path, CancellationToken cancellationToken = default)
    {
        SshSession session = await GetSessionAsync(cancellationToken).ConfigureAwait(false);
        return await session.OpenUnixConnectionChannelAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public async Task<DirectForward> StartForwardAsync(EndPoint bindEP, RemoteEndPoint remoteEP, CancellationToken cancellationToken = default)
    {
        SshSession session = await GetSessionAsync(cancellationToken).ConfigureAwait(false);

        var forward = new DirectForward(_loggers.DirectForwardLogger);
        forward.Start(session, bindEP, remoteEP);
        return forward;
    }

    public async Task<SocksForward> StartSocksForward(EndPoint bindEP, CancellationToken cancellationToken = default)
    {
        SshSession session = await GetSessionAsync(cancellationToken).ConfigureAwait(false);

        var forward = new SocksForward(_loggers.SocksForwardLogger);
        forward.Start(session, bindEP);
        return forward;
    }

    public Task<SftpClient> OpenSftpClientAsync(CancellationToken cancellationToken)
        => OpenSftpClientAsync(null, cancellationToken);

    public async Task<SftpClient> OpenSftpClientAsync(SftpClientOptions? options = null, CancellationToken cancellationToken = default)
    {
        SftpClient sftpClient = new SftpClient(this, options);
        try
        {
            await sftpClient.OpenAsync(cancellationToken).ConfigureAwait(false);
            return sftpClient;
        }
        catch
        {
            sftpClient.Dispose();

            throw;
        }
    }

    internal async Task<SftpChannel> OpenSftpChannelAsync(Action<SshChannel> onAbort, bool explicitConnect, SftpClientOptions options, CancellationToken cancellationToken)
    {
        SshSession session = await GetSessionAsync(cancellationToken, explicitConnect).ConfigureAwait(false);

        var channel = await session.OpenSftpClientChannelAsync(onAbort, cancellationToken).ConfigureAwait(false);

        var sftpChannel = new SftpChannel(channel, options);

        try
        {
            await sftpChannel.ProtocolInitAsync(cancellationToken).ConfigureAwait(false);

            return sftpChannel;
        }
        catch
        {
            sftpChannel.Dispose();

            throw;
        }
    }

    internal static ObjectDisposedException NewObjectDisposedException()
    {
        return new ObjectDisposedException(typeof(SshClient).FullName);
    }

    // For testing.
    internal void ForceConnectionClose()
    {
        Debug.Assert(_session is not null);
        _session.ForceConnectionClose();
    }

    // For testing.
    internal SshConnectionInfo ConnectionInfo
    {
        get
        {
            Debug.Assert(_session is not null);
            return _session.ConnectionInfo;
        }
    }
}
