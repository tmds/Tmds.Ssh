// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public sealed partial class SshClient : IDisposable
    {
        public async Task<SftpClient> OpenSftpClientAsync(CancellationToken ct)
        {
            ChannelContext context = CreateChannel();
            SftpClient? sftpClient = null;
            try
            {
                // Open the session channel.
                await context.SendChannelOpenSessionMessageAsync(ct).ConfigureAwait(false);
                await context.ReceiveChannelOpenConfirmationAsync(ct).ConfigureAwait(false);
                // Request command execution.
                await context.SendChannelSubsystemMessageAsync("sftp", ct).ConfigureAwait(false);
                await context.ReceiveChannelRequestSuccessAsync("Failed to start sftp.", ct).ConfigureAwait(false);

                sftpClient = new SftpClient(context);
                await sftpClient.InitAsync(ct);

                return sftpClient;
            }
            catch
            {
                if (sftpClient != null)
                {
                    sftpClient.Dispose();
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