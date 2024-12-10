// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    // https://datatracker.ietf.org/doc/html/rfc4252 - The "none" Authentication Request
    public sealed class NoneAuth
    {
        public static async Task<AuthResult> TryAuthenticate(UserAuthContext context, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            context.StartAuth(AlgorithmNames.None);

            logger.NoneAuth();

            {
                using var userAuthMsg = CreateNoneRequestMessage(context.SequencePool, context.UserName);
                await context.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
            }

            return await context.ReceiveAuthResultAsync(ct).ConfigureAwait(false);
        }

        private static Packet CreateNoneRequestMessage(SequencePool sequencePool, string userName)
        {
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
            writer.WriteString(userName);
            writer.WriteString("ssh-connection");
            writer.WriteString("none");
            return packet.Move();
        }
    }
}