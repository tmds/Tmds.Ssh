// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    static class SocketExtensions
    {
        public static async Task ConnectAsync(this Socket socket, string host, int port, CancellationToken cancellationToken)
        {
            var tcs = new TaskCompletionSource<bool>();

            using SocketAsyncEventArgs connectSea = new SocketAsyncEventArgs
            {
                UserToken = tcs,
                RemoteEndPoint = new DnsEndPoint(host, port)
            };
            connectSea.Completed += HandleCompletion;

            if (!socket.ConnectAsync(connectSea))
            {
                // synchronous completion
                HandleCompletion(null, connectSea);
                if (connectSea.SocketError != SocketError.Success)
                {
                    throw new SocketException((int)connectSea.SocketError);
                }
            }
            else
            {
                // async completion
                using (cancellationToken.UnsafeRegister(a => Socket.CancelConnectAsync((SocketAsyncEventArgs)a!), connectSea))
                {
                    try
                    {
                        await tcs.Task;
                    }
                    catch (SocketException se) when (se.SocketErrorCode == SocketError.OperationAborted)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        throw;
                    }
                }
            }

            static void HandleCompletion(object? sender, SocketAsyncEventArgs args)
            {
                var argsTcs = (TaskCompletionSource<bool>)args.UserToken;
                if (args.SocketError == SocketError.Success)
                {
                    argsTcs.SetResult(true);
                }
                else
                {
                    argsTcs.SetException(new SocketException((int)args.SocketError));
                }
            }
        }
    }
}