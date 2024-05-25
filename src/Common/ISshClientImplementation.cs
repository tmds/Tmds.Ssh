// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh;

interface ISshClientImplementation
{
    Task ConnectAsync(CancellationToken cancellationToken);
    Task<ISshChannel> OpenRemoteProcessChannelAsync(Type channelType, string command, CancellationToken cancellationToken);
    Task<ISshChannel> OpenTcpConnectionChannelAsync(Type channelType, string host, int port, CancellationToken cancellationToken);
    Task<ISshChannel> OpenUnixConnectionChannelAsync(Type channelType, string path, CancellationToken cancellationToken);
    Task<ISshChannel> OpenSftpClientChannelAsync(Type channelType, CancellationToken cancellationToken);

    void Dispose();
}
