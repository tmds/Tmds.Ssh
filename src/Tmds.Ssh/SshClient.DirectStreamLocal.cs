// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public partial class SshClient
    {
        // MAYDO: maybe add arg to control window size?
        public async Task<Stream> CreateUnixConnectionAsStreamAsync(string socketPath, CancellationToken cancellationToken = default)
        {
            ChannelContext context = CreateChannel();

            using var abortOnCancel = cancellationToken.Register(ctx => ((ChannelContext)ctx!).Cancel(), context);

            ChannelDataStream? stream = null;
            try
            {
                await context.SendChannelOpenDirectStreamLocalMessageAsync(socketPath);
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
