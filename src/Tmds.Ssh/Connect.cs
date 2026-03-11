// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh;

static class Connect
{
    private static ConnectCallback _defaultConnect = TcpConnectAsync;

    public static async Task<Stream> ConnectTcpAsync(string host, int port, CancellationToken cancellationToken)
    {
        var endPoint = new ConnectEndPoint(host, port);
        var context = new ConnectContext(endPoint, NullLoggerFactory.Instance);
        return await _defaultConnect(context, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<Stream> ConnectUnixAsync(UnixDomainSocketEndPoint endPoint, CancellationToken cancellationToken)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(endPoint, cancellationToken).ConfigureAwait(false);

            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();

            throw;
        }
    }

    public static async ValueTask<Stream> ConnectAsync(ConnectCallback? connect, Proxy? proxy, ConnectContext context, CancellationToken cancellationToken)
    {
        connect ??= _defaultConnect;
        if (proxy is null)
        {
            return await connect(context, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            return await proxy.ConnectToProxyAndForward(connect, context, cancellationToken);
        }
    }

    private static async ValueTask<Stream> TcpConnectAsync(ConnectContext context, CancellationToken cancellationToken)
    {
        context.LogConnect();

        // Dual-stack socket: supports both IPv4 and IPv6.
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            // Connect to the remote host
            await socket.ConnectAsync(context.EndPoint.Host, context.EndPoint.Port, cancellationToken).ConfigureAwait(false);

            IPAddress remoteAddress = (socket.RemoteEndPoint as IPEndPoint)!.Address;
            if (remoteAddress.IsIPv4MappedToIPv6)
            {
                remoteAddress = remoteAddress.MapToIPv4();
            }
            context.SetHostIPAddress(remoteAddress);

            socket.NoDelay = true;

            if (context.TcpKeepAlive)
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            }

            return new NetworkStream(socket, ownsSocket: true);
        }
        catch (Exception ex)
        {
            socket.Dispose();

            // ConnectAsync may throw ODE for cancellation
            // when the connection is made just before the token gets cancelled.
            if (ex is ObjectDisposedException)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

            throw;
        }
    }
}
