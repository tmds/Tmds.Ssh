// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh;

public sealed partial class SshClient : IDisposable
{
    private readonly object _gate = new object();
    private SshSession? _session;
    private Task<SshSession>? _connectingTask;
    private readonly SshClientSettings _clientSettings;
    private State _state = State.Initial;

    enum State
    {
        Initial,
        Connecting,
        Connected,
        Disconnected,
        Disposed
    }

    public SshClient(SshClientSettings clientSettings)
    {
        _clientSettings = clientSettings ?? throw new ArgumentNullException(nameof(clientSettings));
    }

    public SshClient(string destination)
        : this(new SshClientSettings(destination))
    { }

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        State state = _state;
        if (state != State.Initial && state != State.Disposed)
        {
            throw new InvalidOperationException($"{nameof(ConnectAsync)} may only be called once.");
        }
        await ConnectCoreAsync(cancellationToken, explicitConnect: true).ConfigureAwait(false);
    }

    private ValueTask<SshSession> ConnectCoreAsync(CancellationToken cancellationToken, bool explicitConnect = false)
    {
        lock (_gate)
        {
            State state = _state;

            if (state == State.Connected ||
                (state == State.Disconnected && !_clientSettings.AutoReconnect))
            {
                return new ValueTask<SshSession>(_session!);
            }

            return ConnectCore(state, cancellationToken, explicitConnect);
        }

        ValueTask<SshSession> ConnectCore(State state, CancellationToken cancellationToken, bool explicitConnect)
        {
            Debug.Assert(Monitor.IsEntered(_gate));

            if (state == State.Disposed)
            {
                throw NewObjectDisposedException();
            }

            if (!explicitConnect && !_clientSettings.AutoConnect && (state == State.Initial || state == State.Connecting))
            {
                throw new InvalidOperationException($"{nameof(ConnectAsync)} must be called and awaited.");
            }

            if (state != State.Connecting)
            {
                _state = State.Connecting;

                if (explicitConnect)
                {
                    _connectingTask = DoConnectAsync(cancellationToken);
                    return new ValueTask<SshSession>(_connectingTask);
                }
                else
                {
                    _connectingTask = DoConnectAsync(default);
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

    private async Task<SshSession> DoConnectAsync(CancellationToken cancellationToken)
    {
        Debug.Assert(Monitor.IsEntered(_gate));
        Debug.Assert(_state == State.Connecting);

        SshSession session = new SshSession(_clientSettings, this);
        _session = session;

        bool success = false;
        try
        {
            await session.ConnectAsync(cancellationToken);
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
        SshSession session = await ConnectCoreAsync(cancellationToken);
        var channel = await session.OpenRemoteProcessChannelAsync(typeof(RemoteProcess), command, cancellationToken).ConfigureAwait(false);

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
        SshSession session = await ConnectCoreAsync(cancellationToken);
        var channel = await session.OpenTcpConnectionChannelAsync(typeof(SshDataStream), host, port, cancellationToken).ConfigureAwait(false);

        return new SshDataStream(channel);
    }

    public async Task<SshDataStream> OpenUnixConnectionAsync(string path, CancellationToken cancellationToken = default)
    {
        SshSession session = await ConnectCoreAsync(cancellationToken);
        var channel = await session.OpenUnixConnectionChannelAsync(typeof(SshDataStream), path, cancellationToken).ConfigureAwait(false);

        return new SshDataStream(channel);
    }

    public async Task<SftpClient> CreateSftpClientAsync(CancellationToken cancellationToken = default)
    {
        SshSession session = await ConnectCoreAsync(cancellationToken);
        var channel = await session.OpenSftpClientChannelAsync(typeof(SftpClient), cancellationToken).ConfigureAwait(false);

        var sftpClient = new SftpClient(channel);

        try
        {
            await sftpClient.ProtocolInitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            sftpClient.Dispose();

            throw;
        }

        return sftpClient;
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
}
