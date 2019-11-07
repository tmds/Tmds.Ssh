// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public partial class SshClient
    {
        // MAYDO: maybe add arg to control window size?
        public Task<ChannelDataStream> CreateTcpConnectionAsStreamAsync(string host, int port, CancellationToken cancellationToken = default)
            => CreateTcpConnectionAsStreamAsync(host, port, IPAddress.Any, 0, cancellationToken);

        // MAYDO: maybe add arg to control window size?
        public async Task<ChannelDataStream> CreateTcpConnectionAsStreamAsync(string host, int port, IPAddress originatorIP, int originatorPort, CancellationToken cancellationToken = default)
        {
            ChannelContext context = CreateChannel();

            using var abortOnCancel = cancellationToken.Register(ctx => ((ChannelContext)ctx!).Abort(), context);

            ChannelDataStream? stream = null;
            try
            {
                await context.SendChannelOpenDirectTcpIpMessageAsync(host, (uint)port, originatorIP, (uint)originatorPort);
                await context.ReceiveChannelOpenConfirmationAsync();
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
                    await context.DisposeAsync();
                }

                throw;
            }
        }
    }
}
