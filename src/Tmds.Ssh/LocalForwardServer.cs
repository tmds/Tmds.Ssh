// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

sealed partial class LocalForwardServer<T> : ForwardServer<T, SshDataStream>
{
    private Socket? _serverSocket;
    private EndPoint? _localEndPoint;
    private RemoteEndPoint? _remoteEndPoint; // When DirectForward.
    private int _id;

    public EndPoint LocalEndPoint
    {
        get
        {
            ThrowIfDisposed();
            return _localEndPoint ?? throw new InvalidOperationException("Not started.");
        }
    }

    internal LocalForwardServer(ILogger<T> logger)
        : base(logger)
    { }

    internal async ValueTask StartDirectForwardAsync(SshSession session, EndPoint bindEP, RemoteEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        Debug.Assert(bindEP is not null);
        CheckBindEndPoint(bindEP);
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        _localEndPoint = bindEP;
        _remoteEndPoint = remoteEndPoint;

        await StartAsync(session, ForwardProtocol.Direct, bindEP.ToString()!, _remoteEndPoint.ToString(), cancellationToken);
    }

    internal async ValueTask StartSocksForwardAsync(SshSession session, EndPoint bindEP, CancellationToken cancellationToken)
    {
        Debug.Assert(bindEP is not null);
        CheckBindEndPoint(bindEP);

        _localEndPoint = bindEP;
        _remoteEndPoint = null;

        await StartAsync(session, ForwardProtocol.Socks, bindEP.ToString()!, targetEndPoint: null, cancellationToken);
    }

    private static void CheckBindEndPoint(EndPoint bindEP)
    {
        ArgumentNullException.ThrowIfNull(bindEP);
        if (bindEP is not IPEndPoint and not UnixDomainSocketEndPoint)
        {
            throw new ArgumentException($"Unsupported EndPoint type: {bindEP.GetType().FullName}.");
        }
    }

    protected override async Task<(Stream?, string)> AcceptAsync()
    {
        Debug.Assert(_serverSocket is not null);
        Socket acceptedSocket = await _serverSocket.AcceptAsync().ConfigureAwait(false);
        try
        {
            string? address = acceptedSocket.RemoteEndPoint?.ToString();
            if (string.IsNullOrEmpty(address))
            {
                address = $"{_listenEndPoint}#{_id++}";
            }

            if (acceptedSocket.ProtocolType == ProtocolType.Tcp)
            {
                acceptedSocket.NoDelay = true;
            }
            NetworkStream networkStream = new NetworkStream(acceptedSocket, ownsSocket: true);

            return (networkStream, address);
        }
        catch
        {
            acceptedSocket.Dispose();

            throw;
        }
    }

    protected override async Task<(Task<SshDataStream>, string)> ConnectToTargetAsync(Stream clientStream, CancellationToken ct)
    {
        SshSession? session = _session;
        Debug.Assert(session is not null);

        Task<SshDataStream> connect;
        RemoteEndPoint? endPoint = _remoteEndPoint;
        if (_protocol == ForwardProtocol.Socks)
        {
            (string host, int port) = await ReadSocks5HostAndPortAsync(clientStream, ct).ConfigureAwait(false);
            connect = session.OpenTcpConnectionChannelAsync(host, port, ct);
            endPoint = new RemoteHostEndPoint(host, port);
        }
        else if (endPoint is RemoteHostEndPoint hostEndPoint)
        {
            connect = session.OpenTcpConnectionChannelAsync(hostEndPoint.Host, hostEndPoint.Port, ct);
        }
        else if (endPoint is RemoteIPEndPoint ipEndPoint)
        {
            connect = session.OpenTcpConnectionChannelAsync(ipEndPoint.Address.ToString(), ipEndPoint.Port, ct);
        }
        else if (endPoint is RemoteUnixEndPoint unixEndPoint)
        {
            connect = session.OpenUnixConnectionChannelAsync(unixEndPoint.Path, ct);
        }
        else
        {
            throw new InvalidOperationException("Invalid endpoint");
        }

        return (connect, endPoint!.ToString()!);
    }

    protected override void Stop()
    {
        _serverSocket?.Dispose();
    }

    protected override ValueTask ListenAsync(CancellationToken cancellationToken)
    {
        EndPoint? bindEP = _localEndPoint;
        Debug.Assert(bindEP is not null);

        bool updateEndPoint = false;
        if (bindEP is IPEndPoint ipEndPoint)
        {
            _serverSocket = new Socket(ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            if (ipEndPoint.Address.Equals(IPAddress.IPv6Any))
            {
                _serverSocket.DualMode = true;
            }
            updateEndPoint = ipEndPoint.Port == 0;
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

        if (updateEndPoint)
        {
            _localEndPoint = _serverSocket.LocalEndPoint!;
            UpdateListenEndPoint(_localEndPoint.ToString()!);
        }

        return default;
    }
}
