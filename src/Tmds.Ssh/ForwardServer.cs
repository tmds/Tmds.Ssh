// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Tmds.Ssh.ForwardServerLogging;

namespace Tmds.Ssh;

// Implements forwarding on behalf of the public class 'T".
sealed partial class ForwardServer<T> : IDisposable
{
    private enum ForwardProtocol
    {
        Direct = 1,
        Socks
    }

    // Sentinel stop reasons.
    private static readonly Exception ConnectionClosed = new();
    private static readonly Exception Disposed = new();

    private readonly ILogger<T> _logger;
    private readonly CancellationTokenSource _cancel;

    private SshSession? _session; 
    private Func<NetworkStream, CancellationToken, ValueTask<(Task<SshDataStream>, RemoteEndPoint)>>? _acceptHandler;
    private Socket? _serverSocket;
    private ForwardProtocol _protocol;
    private EndPoint? _localEndPoint;
    private RemoteEndPoint? _remoteEndPoint;
    private CancellationTokenRegistration _ctr;
    private Exception? _stopReason;

    private bool IsDisposed => ReferenceEquals(_stopReason, Disposed);

    public EndPoint LocalEndPoint
    {
        get
        {
            ThrowIfStopped();
            return _localEndPoint ?? throw new InvalidOperationException("Not started.");
        }
    }

    public CancellationToken Stopped
    {
        get
        {
            ThrowIfDisposed();
            return _cancel.Token;
        }
    }

    public void ThrowIfStopped()
    {
        Exception? stopReason = _stopReason;
        if (ReferenceEquals(stopReason, Disposed))
        {
            throw new ObjectDisposedException(typeof(T).FullName);
        }
        else if (ReferenceEquals(stopReason, ConnectionClosed))
        {
            throw _session!.CreateCloseException();
        }
        else if (stopReason is not null)
        {
            throw new SshException($"{nameof(T)} stopped due to an unexpected error.", stopReason);
        }
    }

    public void Dispose()
        => Stop(Disposed);

    internal ForwardServer(ILogger<T> logger)
    {
        _logger = logger;
        _cancel = new();
    }

    private static void CheckBindEndPoint(EndPoint bindEP)
    {
        ArgumentNullException.ThrowIfNull(bindEP);
        if (bindEP is not IPEndPoint and not UnixDomainSocketEndPoint)
        {
            throw new ArgumentException($"Unsupported EndPoint type: {bindEP.GetType().FullName}.");
        }
    }

    private void Start(SshSession session, EndPoint bindEP, ForwardProtocol forwardProtocol, Func<NetworkStream, CancellationToken, ValueTask<(Task<SshDataStream>, RemoteEndPoint)>> acceptHandler, RemoteEndPoint? remoteEndPoint = null)
    {
        // Assign to bindEP in case we fail to bind/listen so we have an address for logging.
        _session = session;
        _localEndPoint = bindEP;
        _remoteEndPoint = remoteEndPoint;
        _acceptHandler = acceptHandler;
        _protocol = forwardProtocol;

        try
        {
            if (bindEP is IPEndPoint ipEndPoint)
            {
                _serverSocket = new Socket(ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                if (ipEndPoint.Address.Equals(IPAddress.IPv6Any))
                {
                    _serverSocket.DualMode = true;
                }
            }
            else if (bindEP is UnixDomainSocketEndPoint unixEndPoint)
            {
                _serverSocket = new Socket(unixEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Unspecified);
            }
            else
            {
                // Type must be validated before calling this method.
                throw new InvalidOperationException($"Unsupported EndPoint type: {bindEP.GetType().FullName}.");
            }

            _serverSocket.Bind(bindEP);
            _serverSocket.Listen();

            EndPoint localEndPoint = _serverSocket.LocalEndPoint!;
            _localEndPoint = localEndPoint;

            _ctr = _session.ConnectionClosed.UnsafeRegister(o => ((ForwardServer<T>)o!).Stop(ConnectionClosed), this);

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
            if (_protocol == ForwardProtocol.Direct)
            {
                Debug.Assert(_remoteEndPoint is not null);
                _logger.DirectForwardStart(localEndPoint, _remoteEndPoint!);
            }
            else if (_protocol == ForwardProtocol.Socks)
            {
                _logger.SocksForwardStart(localEndPoint);
            }
            else
            {
                throw new IndexOutOfRangeException(_protocol.ToString());
            }

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

    private async Task Accept(Socket acceptedSocket, EndPoint localEndPoint)
    {
        Debug.Assert(_acceptHandler is not null);
        SshDataStream? forwardStream = null;
        EndPoint? peerEndPoint = null;
        RemoteEndPoint? remoteEndPoint = _remoteEndPoint;
        try
        {
            peerEndPoint = acceptedSocket.RemoteEndPoint!;

            _logger.AcceptConnection(localEndPoint, peerEndPoint);

            if (acceptedSocket.ProtocolType == ProtocolType.Tcp)
            {
                acceptedSocket.NoDelay = true;
            }
            NetworkStream networkStream = new NetworkStream(acceptedSocket, ownsSocket: true);

            Task<SshDataStream> openStream;
            (openStream, remoteEndPoint) = await _acceptHandler(networkStream, _cancel!.Token).ConfigureAwait(false);
            forwardStream = await openStream.ConfigureAwait(false);

            _ = ForwardConnectionAsync(networkStream, forwardStream, peerEndPoint, remoteEndPoint);
        }
        catch (Exception ex)
        {
            _logger.ForwardConnectionFailed(peerEndPoint, remoteEndPoint, ex);

            acceptedSocket.Dispose();
            forwardStream?.Dispose();
        }
    }

    private async Task ForwardConnectionAsync(NetworkStream socketStream, SshDataStream sshStream, EndPoint peerEndPoint, RemoteEndPoint remoteEndPoint)
    {
        Exception? exception = null;
        try
        {
            _logger.ForwardConnection(peerEndPoint, remoteEndPoint);
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
                _logger.ForwardConnectionClosed(peerEndPoint, remoteEndPoint);
            }
            else
            {
                _logger.ForwardConnectionAborted(peerEndPoint, remoteEndPoint, exception);
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

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(IsDisposed, typeof(T));
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
                _logger.ForwardStopped(_localEndPoint);
            }
            else if (ReferenceEquals(stopReason, ConnectionClosed))
            {
                if (_logger.IsEnabled(LogLevel.Error))
                {
                    _logger.ForwardAborted(_localEndPoint, _session!.CreateCloseException());
                }
            }
            else
            {
                _logger.ForwardAborted(_localEndPoint, stopReason);
            }
            _ctr.Dispose();
            _serverSocket?.Dispose();
        }

        _cancel.Cancel();
    }
}
