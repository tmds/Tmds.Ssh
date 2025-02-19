// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using System.Net.Sockets;

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
        if (bindEP is not RemoteIPListenEndPoint and not RemoteUnixEndPoint)
        {
            throw new ArgumentException($"Unsupported RemoteEndPoint type: {bindEP.GetType().FullName}.");
        }
    }

    private static void CheckTargetEndPoint(EndPoint localEndPoint)
    {
        ArgumentNullException.ThrowIfNull(localEndPoint);
        if (localEndPoint is DnsEndPoint dnsEndPoint)
        {
            ArgumentValidation.ValidatePort(dnsEndPoint.Port, allowZero: false, nameof(localEndPoint));
            ArgumentValidation.ValidateHost(dnsEndPoint.Host, allowEmpty: false, nameof(localEndPoint));
        }
        else if (localEndPoint is IPEndPoint ipEndPoint)
        {
            ArgumentValidation.ValidatePort(ipEndPoint.Port, allowZero: false, nameof(localEndPoint));
        }
        else if (localEndPoint is UnixDomainSocketEndPoint unixEndPoint)
        { }
        else
        {
            throw new ArgumentException($"Unsupported EndPoint type: {localEndPoint.GetType().FullName}.");
        }
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
        else if (endPoint is UnixDomainSocketEndPoint unixEndPoint)
        {
            connect = Connect.ConnectUnixAsync(unixEndPoint, ct);
        }
        else
        {
            throw new InvalidOperationException("Invalid endpoint");
        }

        return (connect, endPoint!.ToString()!);
    }

    protected override void Stop()
    {
        _listener?.Stop();
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
        else if (bindEP is RemoteUnixEndPoint unixEndPoint)
        {
            _listener = new RemoteListener();
            await _listener.OpenUnixAsync(_session, unixEndPoint.Path, cancellationToken).ConfigureAwait(false);
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
