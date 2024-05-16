// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    // MAYDO: maybe add arg to control window size?
    // TODO: support envvars.
    public class ExecuteCommandOptions
    {
        internal static readonly UTF8Encoding Utf8NoBom =
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        public Encoding StandardInputEncoding { get; set; } = Utf8NoBom;
        public Encoding StandardErrorEncoding { get; set; } = Utf8NoBom;
        public Encoding StandardOutputEncoding { get; set; } = Utf8NoBom;
    }

    public partial class SshClient
    {
        public Task<RemoteProcess> ExecuteCommandAsync(string command, CancellationToken ct)
            => ExecuteCommandAsync(command, configure: null, ct);

        public async Task<RemoteProcess> ExecuteCommandAsync(string command, Action<ExecuteCommandOptions>? configure = null, CancellationToken ct = default)
        {
            ChannelContext context = CreateChannel();

            var options = new ExecuteCommandOptions();
            configure?.Invoke(options);

            Encoding standardInputEncoding = options.StandardInputEncoding;
            Encoding standardErrorEncoding = options.StandardErrorEncoding;
            Encoding standardOutputEncoding = options.StandardOutputEncoding;

            RemoteProcess? remoteProcess = null;
            try
            {
                // Open the session channel.
                {
                    await context.SendChannelOpenSessionMessageAsync(ct).ConfigureAwait(false);
                    await context.ReceiveChannelOpenConfirmationAsync(ct).ConfigureAwait(false);
                }

                // Request command execution.
                {
                    await context.SendExecCommandMessageAsync(command, ct).ConfigureAwait(false);
                    await context.ReceiveChannelRequestSuccessAsync("Failed to execute command.", ct).ConfigureAwait(false);
                }
                remoteProcess = new RemoteProcess(context, standardInputEncoding, standardErrorEncoding, standardOutputEncoding);
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
