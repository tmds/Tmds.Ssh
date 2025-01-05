// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Net.Sockets;

namespace Tmds.Ssh;

abstract class Connect
{
    public abstract ValueTask<Stream> ConnectAsync(ConnectContext context, CancellationToken cancellationToken);
}

sealed class TcpConnect : Connect
{
    public override async ValueTask<Stream> ConnectAsync(ConnectContext context, CancellationToken cancellationToken)
    {
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