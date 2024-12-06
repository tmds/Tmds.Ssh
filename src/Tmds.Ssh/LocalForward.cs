// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

public sealed class LocalForward : IDisposable
{
    // Sentinel stop reasons.
    private static readonly Exception ConnectionClosed = new();
    private static readonly Exception Disposed = new();

    private readonly SshSession _session;
    private readonly ILogger<LocalForward> _logger;
    private readonly CancellationTokenSource _cancel;
 
    private Func<CancellationToken, Task<SshDataStream>>? _connectToRemote;
    private Socket? _serverSocket;
    private EndPoint? _localEndPoint;
    private CancellationTokenRegistration _ctr;
    private Exception? _stopReason;
    private string _remoteEndPoint;

    private bool IsDisposed => ReferenceEquals(_stopReason, Disposed);

    internal LocalForward(SshSession session, ILogger<LocalForward> logger)
    {
        _logger = logger;
        _session = session;
        _cancel = new();

        _remoteEndPoint = "";
    }

    internal void StartTcpForward(EndPoint bindEndpoint, string remoteHost, int remotePort)
    {
        ArgumentNullException.ThrowIfNull(bindEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(remoteHost);
        if (remotePort < 0 || remotePort > 0xffff)
        {
            throw new ArgumentException(nameof(remotePort));
        }
        if (bindEndpoint is not IPEndPoint)
        {
            throw new ArgumentException($"Unsupported EndPoint type: {bindEndpoint.GetType().FullName}.");
        }

        _remoteEndPoint = $"{remoteHost}:{remotePort}";
        _connectToRemote = async ct => await _session.OpenTcpConnectionChannelAsync(remoteHost, remotePort, ct).ConfigureAwait(false);

        Start(bindEndpoint);
    }

    private void Start(EndPoint bindEndpoint)
    {
        // Assign to bindEndPoint in case we fail to bind/listen so we have an address for logging.
        _localEndPoint = bindEndpoint;

        try
        {
            if (bindEndpoint is IPEndPoint ipEndPoint)
            {
                _serverSocket = new Socket(ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            }
            else
            {
                // Type must be validated before calling this method.
                throw new InvalidOperationException($"Unsupported EndPoint type: {bindEndpoint.GetType().FullName}.");
            }

            _serverSocket.Bind(bindEndpoint);
            _serverSocket.Listen();

            EndPoint localEndPoint = _serverSocket.LocalEndPoint!;
            _localEndPoint = localEndPoint;

            _ctr = _session.ConnectionClosed.UnsafeRegister(o => ((LocalForward)o!).Stop(ConnectionClosed), this);

            _ = AcceptLoop(localEndPoint);
        }
        catch (Exception ex)
        {
            Stop(ex);

            throw;
        }
    }

    private async Task AcceptLoop(EndPoint localEndPoint)
    {
        try
        {
            _logger.ForwardStart(localEndPoint, _remoteEndPoint);
            while (true)
            {
                Socket acceptedSocket = await _serverSocket!.AcceptAsync().ConfigureAwait(false);
                _ = Accept(acceptedSocket, localEndPoint);
            }
        }
        catch (Exception ex)
        {
            Stop(ex);
        }
    }

    private async Task Accept(Socket acceptedSocket, EndPoint localEndpoint)
    {
        Debug.Assert(_connectToRemote is not null);
        SshDataStream? forwardStream = null;
        EndPoint? peerEndPoint = null;
        try
        {
            peerEndPoint = acceptedSocket.RemoteEndPoint!;
            _logger.AcceptConnection(localEndpoint, peerEndPoint, _remoteEndPoint);
            acceptedSocket.NoDelay = true;

            // We may want to add a timeout option, and the ability to stop the lister on some conditions like nr of successive fails to connect to the remote.
            forwardStream = await _connectToRemote(_cancel!.Token).ConfigureAwait(false);
            _ = ForwardConnectionAsync(new NetworkStream(acceptedSocket, ownsSocket: true), forwardStream, peerEndPoint);
        }
        catch (Exception ex)
        {
            _logger.ForwardConnectionFailed(peerEndPoint, _remoteEndPoint, ex);

            acceptedSocket.Dispose();
            forwardStream?.Dispose();
        }
    }

    private async Task ForwardConnectionAsync(NetworkStream socketStream, SshDataStream sshStream, EndPoint peerEndPoint)
    {
        Exception? exception = null;
        try
        {
            _logger.ForwardConnection(peerEndPoint, _remoteEndPoint);
            Task first, second;
            try
            {
                Task copy1 = CopyTillEofAsync(socketStream, sshStream, sshStream.WriteMaxPacketDataLength);
                Task copy2 = CopyTillEofAsync(sshStream, socketStream, sshStream.ReadMaxPacketDataLength);

                first = await Task.WhenAny(copy1, copy2).ConfigureAwait(false);
                second = first == copy1 ? copy2 : copy1;
            }
            finally
            {
                // When the copy stops in one direction, stop it in the other direction too.
                // Though TCP allows data still to be received when the writing is shutdown
                // application protocols (usually) follow the pattern of only closing
                // when they will no longer receive.
                socketStream.Dispose();
                sshStream.Dispose();
            }
            // The dispose will cause the second copy to stop.
            await second.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);

            await first.ConfigureAwait(false); // Throws if faulted.
        }
        catch (Exception ex)
        {
            exception = ex;
        }
        finally
        {
            if (exception is null)
            {
                _logger.ForwardConnectionClosed(peerEndPoint, _remoteEndPoint);
            }
            else
            {
                _logger.ForwardConnectionAborted(peerEndPoint, _remoteEndPoint, exception);
            }
        }

        static async Task CopyTillEofAsync(Stream from, Stream to, int bufferSize)
        {
            await from.CopyToAsync(to, bufferSize).ConfigureAwait(false);
            if (to is NetworkStream ns)
            {
                ns.Socket.Shutdown(SocketShutdown.Send);
            }
            else if (to is SshDataStream ds)
            {
                ds.WriteEof();
            }
        }
    }

    public EndPoint? EndPoint
    {
        get
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            return _localEndPoint;
        }
    }

    public CancellationToken ForwardStopped
    {
        get
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            return _cancel.Token;
        }
    }

    public void ThrowIfStopped()
    {
        Exception? stopReason = _stopReason;
        if (ReferenceEquals(stopReason, Disposed))
        {
            throw new ObjectDisposedException(typeof(LocalForward).FullName);
        }
        else if (ReferenceEquals(stopReason, ConnectionClosed))
        {
            throw _session.CreateCloseException();
        }
        else if (stopReason is not null)
        {
            throw new SshException($"{nameof(LocalForward)} stopped due to an unexpected error.", stopReason);
        }
    }

    private void Stop(Exception stopReason)
    {
        bool disposing = ReferenceEquals(stopReason, Disposed);
        if (disposing)
        {
            if (Interlocked.Exchange(ref _stopReason, Disposed) != null)
            {
                return;
            }
        }
        else
        {
            if (Interlocked.CompareExchange(ref _stopReason, stopReason, null) != null)
            {
                return;
            }
        }

        if (_localEndPoint is not null)
        {
            if (IsDisposed)
            {
                _logger.ForwardStopped(_localEndPoint, _remoteEndPoint);
            }
            else if (ReferenceEquals(stopReason, ConnectionClosed))
            {
                if (_logger.IsEnabled(LogLevel.Error))
                {
                    _logger.ForwardAborted(_localEndPoint, _remoteEndPoint, _session.CreateCloseException());
                }
            }
            else
            {
                _logger.ForwardAborted(_localEndPoint, _remoteEndPoint, stopReason);
            }
            _ctr.Dispose();
            _localEndPoint = null;
            _serverSocket?.Dispose();
        }

        _cancel.Cancel();
    }

    public void Dispose()
        => Stop(Disposed);
}