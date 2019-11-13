// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public partial class SshClient
    {
        // MAYDO: maybe add arg to control window size?
        // TODO: support envvars.
        public async Task<RemoteProcess> ExecuteCommandAsync(string command, CancellationToken cancellationToken = default)
        {
            ChannelContext context = CreateChannel();

            using var abortOnCancel = cancellationToken.Register(ctx => ((ChannelContext)ctx!).Cancel(), context);

            RemoteProcess? remoteProcess = null;
            try
            {
                // Open the session channel.
                {
                    await context.SendChannelOpenSessionMessageAsync();
                    await context.ReceiveChannelOpenConfirmationAsync();
                }

                // Request command execution.
                {
                    await context.SendExecCommandMessageAsync(command);
                    await context.ReceiveChannelRequestSuccessAsync();
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
