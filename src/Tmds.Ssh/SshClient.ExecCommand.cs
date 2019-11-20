// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public partial class SshClient
    {
        // MAYDO: maybe add arg to control window size?
        // TODO: support envvars.
        public async Task<RemoteProcess> ExecuteCommandAsync(string command, CancellationToken ct = default)
        {
            ChannelContext context = CreateChannel();

            RemoteProcess? remoteProcess = null;
            try
            {
                // Open the session channel.
                {
                    await context.SendChannelOpenSessionMessageAsync(ct);
                    await context.ReceiveChannelOpenConfirmationAsync(ct);
                }

                // Request command execution.
                {
                    await context.SendExecCommandMessageAsync(command, ct);
                    await context.ReceiveChannelRequestSuccessAsync(ct);
                }
                remoteProcess = new RemoteProcess(context);
                return remoteProcess;
            }
            catch
            {
                if (remoteProcess != null)
                {
                    remoteProcess.Dispose();
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
