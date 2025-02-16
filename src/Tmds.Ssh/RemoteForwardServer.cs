// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

sealed partial class RemoteForwardServer<T> : ForwardServer<T, Stream>
{
    private RemoteListener? _listener;
    private RemoteEndPoint? _remoteEndPoint;
    private EndPoint? _localEndPoint; // When DirectForward.
    private int _id;

    public RemoteEndPoint RemoteEndPoint
    {
        get
        {
            ThrowIfDisposed();
            return _remoteEndPoint ?? throw new InvalidOperationException("Not started.");
        }
    }

    internal RemoteForwardServer(ILogger<T> logger)
        : base(logger)
    { }

    internal async ValueTask StartDirectForwardAsync(SshSession session, RemoteEndPoint bindEP, EndPoint localEndPoint, CancellationToken cancellationToken)
    {
        Debug.Assert(bindEP is not null);
        CheckBindEndPoint(bindEP);
        CheckTargetEndPoint(localEndPoint);

        _remoteEndPoint = bindEP;
        _localEndPoint = localEndPoint;

        await StartAsync(session, ForwardProtocol.Direct, bindEP.ToString()!, localEndPoint.ToString(), cancellationToken);
    }

    private static void CheckBindEndPoint(RemoteEndPoint bindEP)
    {
        ArgumentNullException.ThrowIfNull(bindEP);
        // TODO...
    }

    private static void CheckTargetEndPoint(EndPoint targetEP)
    {
        ArgumentNullException.ThrowIfNull(targetEP);
        // TODO...
    }

    protected override async Task<(Stream?, string)> AcceptAsync()
    {
        Debug.Assert(_listener is not null);
        using var remoteConnection = await _listener.AcceptAsync().ConfigureAwait(false);
        if (!remoteConnection.HasStream)
        {
            return default;
        }

        string? address = remoteConnection.RemoteEndPoint?.ToString();
        if (string.IsNullOrEmpty(address))
        {
            address = $"{_listenEndPoint}#{_id++}";
        }

        return (remoteConnection.MoveStream(), address);
    }

    protected override async Task<(Task<Stream>, string)> ConnectToTargetAsync(Stream clientStream, CancellationToken ct)
    {
        Task<Stream> connect;
        EndPoint? endPoint = _localEndPoint;
        if (_protocol == ForwardProtocol.Socks)
        {
            (string host, int port) = await ReadSocks5HostAndPortAsync(clientStream, ct).ConfigureAwait(false);
            endPoint = new DnsEndPoint(host, port);
        }
        if (endPoint is IPEndPoint hostEndPoint)
        {
            connect = Connect.ConnectTcpAsync(hostEndPoint.Address.ToString(), hostEndPoint.Port, ct);
        }
        else if (endPoint is DnsEndPoint dnsEndPoint)
        {
            connect = Connect.ConnectTcpAsync(dnsEndPoint.Host, dnsEndPoint.Port, ct);
        }
        else
        {
            throw new InvalidOperationException("Invalid endpoint");
        }

        return (connect, endPoint!.ToString()!);
    }

    protected override void Stop()
    {
        _listener?.Dispose();
    }

    protected override async ValueTask ListenAsync(CancellationToken cancellationToken)
    {
        Debug.Assert(_session is not null);
        RemoteEndPoint? bindEP = _remoteEndPoint;
        Debug.Assert(bindEP is not null);

        bool updateEndPoint = false;
        if (bindEP is RemoteIPListenEndPoint ipEndPoint)
        {
            _listener = new RemoteListener();
            await _listener.OpenTcpAsync(_session, ipEndPoint.Address, ipEndPoint.Port, cancellationToken).ConfigureAwait(false);

            updateEndPoint = ipEndPoint.Port == 0;
        }
        else
        {
            // Type must be validated before calling this method.
            throw new InvalidOperationException($"Unsupported EndPoint type: {bindEP.GetType().FullName}.");
        }

        if (updateEndPoint)
        {
            _remoteEndPoint = _listener.ListenEndPoint;
            UpdateListenEndPoint(_remoteEndPoint.ToString()!);
        }
    }
}
