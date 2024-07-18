// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    // https://datatracker.ietf.org/doc/html/rfc4252 - "none" method
    sealed class None
    {
        public static async Task<bool> TryAuthenticate(UserAuthContext context, SshConnectionInfo connectionInfo, ILogger logger, CancellationToken ct)
        {
            {
                using var noneAuthMsg = CreateRequestMessage(context.SequencePool, context.UserName);
                await context.SendPacketAsync(noneAuthMsg.Move(), ct).ConfigureAwait(false);
            }

            return await context.ReceiveAuthIsSuccesfullAsync(ct).ConfigureAwait(false);
        }

        private static Packet CreateRequestMessage(SequencePool sequencePool, string userName)
        {
            /*
                byte      SSH_MSG_USERAUTH_REQUEST
                string    user name
                string    service name
                string    "none"
             */
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