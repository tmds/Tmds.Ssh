// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public partial class SshClient
    {
        // MAYDO: maybe add arg to control window size?
        public async Task<Stream> CreateUnixConnectionAsStreamAsync(string socketPath, CancellationToken ct = default)
        {
            ChannelContext context = CreateChannel();

            ChannelDataStream? stream = null;
            try
            {
                await context.SendChannelOpenDirectStreamLocalMessageAsync(socketPath, ct);
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
