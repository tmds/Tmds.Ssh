// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    // https://datatracker.ietf.org/doc/html/rfc4252 - Password Authentication Method: "password"
    public sealed class PasswordAuth
    {
        public static async Task<AuthResult> TryAuthenticate(PasswordCredential passwordCredential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            int attempt = 0;
            while (true)
            {
                var ctx = new PasswordPromptContext(connectionInfo, ++attempt);
                string? password = await passwordCredential.GetPasswordAsync(ctx, ct).ConfigureAwait(false);

                if (password is null)
                {
                    return attempt == 1 ? AuthResult.Skipped : AuthResult.Failure;
                }

                context.StartAuth(AlgorithmNames.Password);

                logger.PasswordAuth();

                {
                    using var userAuthMsg = CreatePasswordRequestMessage(context.SequencePool, context.UserName, password);
                    await context.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                }

                AuthResult result = await context.ReceiveAuthResultAsync(ct).ConfigureAwait(false);
                if (result == AuthResult.Failure)
                {
                    continue;
                }
                return result;
            }
        }

        private static Packet CreatePasswordRequestMessage(SequencePool sequencePool, string userName, string password)
        {
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
            writer.WriteString(userName);
            writer.WriteString("ssh-connection");
            writer.WriteString("password");
            writer.WriteBoolean(false);
            writer.WriteString(password);
            return packet.Move();
        }
   }
}