// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public partial class SshClient
    {
        // MAYDO: maybe add arg to control window size?
        public Task<ChannelDataStream> CreateTcpConnectionAsStreamAsync(string host, int port, CancellationToken ct = default)
            => CreateTcpConnectionAsStreamAsync(host, port, IPAddress.Any, 0, ct);

        // MAYDO: maybe add arg to control window size?
        public async Task<ChannelDataStream> CreateTcpConnectionAsStreamAsync(string host, int port, IPAddress originatorIP, int originatorPort, CancellationToken ct = default)
        {
            ChannelContext context = CreateChannel();

            ChannelDataStream? stream = null;
            try
            {
                await context.SendChannelOpenDirectTcpIpMessageAsync(host, (uint)port, originatorIP, (uint)originatorPort, ct);
                await context.ReceiveChannelOpenConfirmationAsync(ct);
                stream = new ChannelDataStream(context);
                return stream;
            }
            catch
            {
                if (stream != null)
                {
                    await stream.DisposeAsync();
                }
                else
                {
                    context.Dispose();
                }

                throw;
            }
        }
    }
}
