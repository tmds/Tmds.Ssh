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

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
        try
        {
            // Connect to the remote host
            await socket.ConnectAsync(context.EndPoint.Host, context.EndPoint.Port, cancellationToken).ConfigureAwait(false);

            context.SetHostIPAddress((socket.RemoteEndPoint as IPEndPoint)!.Address);

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
