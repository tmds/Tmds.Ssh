// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    // MAYDO: maybe add arg to control window size?
    public class UnixConnectionOptions
    {

    }

    public partial class SshClient
    {
        public Task<Stream> CreateUnixConnectionAsStreamAsync(string socketPath, CancellationToken ct)
            => CreateUnixConnectionAsStreamAsync(socketPath, configure: null, ct);

        public async Task<Stream> CreateUnixConnectionAsStreamAsync(string socketPath, Action<UnixConnectionOptions>? configure = null, CancellationToken ct = default)
        {
            ChannelContext context = CreateChannel();

            ChannelDataStream? stream = null;
            try
            {
                await context.SendChannelOpenDirectStreamLocalMessageAsync(socketPath, ct).ConfigureAwait(false);
                await context.ReceiveChannelOpenConfirmationAsync(ct).ConfigureAwait(false);
                stream = new ChannelDataStream(context);
                return stream;
            }
            catch
            {
                if (stream != null)
                {
                    await stream.DisposeAsync().ConfigureAwait(false);
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
