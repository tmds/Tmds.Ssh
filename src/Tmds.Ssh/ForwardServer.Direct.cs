// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

sealed partial class ForwardServer<T> : IDisposable
{
    internal void StartDirectForward(SshSession session, EndPoint bindEP, RemoteEndPoint remoteEndPoint)
    {
        CheckBindEndPoint(bindEP);
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        Func<NetworkStream, CancellationToken, ValueTask<(Task<SshDataStream>, RemoteEndPoint)>> handleAccept;
        if (remoteEndPoint is RemoteDnsEndPoint dnsEndPoint)
        {
            handleAccept = (NetworkStream clientStream, CancellationToken ct) =>
            {
                var open = session.OpenTcpConnectionChannelAsync(dnsEndPoint.Host, dnsEndPoint.Port, ct);
                return ValueTask.FromResult((open, remoteEndPoint));
            };
        }
        else if (remoteEndPoint is RemoteIPEndPoint ipEndPoint)
        {
            handleAccept = (NetworkStream clientStream, CancellationToken ct) =>
            {
                var open = session.OpenTcpConnectionChannelAsync(ipEndPoint.Address.ToString(), ipEndPoint.Port, ct);
                return ValueTask.FromResult((open, remoteEndPoint));
            };
        }
        else if (remoteEndPoint is RemoteUnixEndPoint unixEndPoint)
        {
            handleAccept = (NetworkStream clientStream, CancellationToken ct) =>
            {
                var open = session.OpenUnixConnectionChannelAsync(unixEndPoint.Path, ct);
                return ValueTask.FromResult((open, remoteEndPoint));
            };
        }
        else
        {
            throw new ArgumentException($"Unsupported RemoteEndPoint type: {remoteEndPoint.GetType().FullName}.");
        }

        Start(session, bindEP, ForwardProtocol.Direct, handleAccept, remoteEndPoint);
    }
}
