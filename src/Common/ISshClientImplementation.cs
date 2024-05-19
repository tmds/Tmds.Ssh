// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh;

interface ISshClientImplementation
{
    Task ConnectAsync(CancellationToken cancellationToken);
    Task<ISshChannel> OpenRemoteProcessChannelAsync(string command, CancellationToken cancellationToken);
    Task<ISshChannel> OpenTcpConnectionChannelAsync(string host, int port, CancellationToken cancellationToken);
    Task<ISshChannel> OpenUnixConnectionChannelAsync(string path, CancellationToken cancellationToken);
    Task<ISshChannel> OpenSftpClientChannelAsync(CancellationToken cancellationToken);

    void Dispose();
}