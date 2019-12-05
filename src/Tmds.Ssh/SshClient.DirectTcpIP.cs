// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    // MAYDO: maybe add arg to control window size?
    public class TcpConnectionOptions
    {
        public IPAddress OriginatorIP { get; set; } = IPAddress.Any;
        public int OriginatorPort { get; set; } = 0;
    }

    public partial class SshClient
    {
        public Task<ChannelDataStream> CreateTcpConnectionAsStreamAsync(string host, int port, CancellationToken ct)
            => CreateTcpConnectionAsStreamAsync(host, port, configure: null, ct);

        public async Task<ChannelDataStream> CreateTcpConnectionAsStreamAsync(string host, int port, Action<TcpConnectionOptions>? configure = null, CancellationToken ct = default)
        {
            ChannelContext context = CreateChannel();

            IPAddress originatorIP = IPAddress.Any;
            int originatorPort = 0;
            if (configure != null)
            {
                TcpConnectionOptions options = new TcpConnectionOptions();
                configure(options);
                originatorIP = options.OriginatorIP;
                originatorPort = options.OriginatorPort;
            }

            ChannelDataStream? stream = null;
            try
            {
                await context.SendChannelOpenDirectTcpIpMessageAsync(host, (uint)port, originatorIP, (uint)originatorPort, ct).ConfigureAwait(false);
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
