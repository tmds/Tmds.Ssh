// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Threading.Channels;

namespace Tmds.Ssh;

public sealed class RemoteListener : IDisposable
{
    // Sentinel stop reasons.
    private static readonly Exception ConnectionClosed = new();
    private static readonly Exception Disposed = new();
    private static readonly Exception Stopped = new();

    private readonly Channel<RemoteConnection> _connectionChannel;

    public RemoteEndPoint ListenEndPoint => _listenEndPoint ?? throw new InvalidOperationException("Not started");

    private SshSession? _session;
    private RemoteEndPoint? _listenEndPoint;
    private Name _forwardType;
    private CancellationTokenRegistration _ctr;
    private Exception? _stopReason;

    public void Stop()
        => Stop(Stopped);

    public void Dispose()
        => Stop(Disposed);

    public async ValueTask<(SshDataStream? Stream, RemoteEndPoint? EndPoint)> AcceptAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            if (!await _connectionChannel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                Exception? stopReason = _stopReason;
                if (ReferenceEquals(stopReason, Stopped))
                {
                    // return 'null' when the user called 'Stop' to indicate no more connections should be accepted.
                    return default;
                }
                else if (ReferenceEquals(stopReason, Disposed))
                {
                    throw new ObjectDisposedException(GetType().FullName);
                }
                else if (ReferenceEquals(stopReason, ConnectionClosed))
                {
                    throw _session!.CreateCloseException();
                }
                else
                {
                    throw new SshException($"{GetType().FullName} stopped due to an unexpected error.", stopReason);
                }
            }

            // TryRead may return false if we're competing with Stop.
            if (_connectionChannel.Reader.TryRead(out RemoteConnection remoteConnection))
            {
                return (remoteConnection.Stream, remoteConnection.RemoteEndPoint);
            }
        }
    }

    private void Stop(Exception stopReason)
    {
        if (Interlocked.CompareExchange(ref _stopReason, stopReason, null) != null)
        {
            return;
        }

        if (_listenEndPoint is not null)
        {
            _ctr.Dispose();

            string address = ((RemoteIPListenEndPoint)_listenEndPoint).Address;
            ushort port = (ushort)((RemoteIPListenEndPoint)_listenEndPoint).Port;
            _session?.StopRemoteForward(_forwardType, address, port);

            _connectionChannel.Writer.Complete();

            while (_connectionChannel.Reader.TryRead(out RemoteConnection connection))
            {
                connection.Stream.Dispose();
            }
        }
    }

    internal RemoteListener()
    {
        _connectionChannel = Channel.CreateUnbounded<RemoteConnection>();
    }

    private async Task OpenAsync(SshSession session, Name forwardType, string address, ushort port, CancellationToken cancellationToken)
    {
        _session = session;
        _forwardType = forwardType;

        try
        {
            port = await _session.StartRemoteForwardAsync(forwardType, address, port, _connectionChannel.Writer, cancellationToken).ConfigureAwait(false);
            _listenEndPoint = new RemoteIPListenEndPoint(address, port);
            _ctr = _session.ConnectionClosed.UnsafeRegister(o => ((RemoteListener)o!).Stop(ConnectionClosed), this);
        }
        catch (Exception ex)
        {
            Stop(ex);

            throw;
        }
    }

    internal Task OpenTcpAsync(SshSession session, string address, int port, CancellationToken cancellationToken)
    {
        ArgumentValidation.ValidateIPListenAddress(address);
        ArgumentValidation.ValidatePort(port, allowZero: true);

        return OpenAsync(session, AlgorithmNames.ForwardTcpIp, address, (ushort)port, cancellationToken);
    }
}
