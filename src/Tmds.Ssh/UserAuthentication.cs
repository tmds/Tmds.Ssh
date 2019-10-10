// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    internal delegate Task AuthenticateUserAsyncDelegate(SshConnection connection, ILogger logger, SshClientSettings settings, CancellationToken token);

    // Authentication Protocol: https://tools.ietf.org/html/rfc4252.
    sealed class UserAuthentication
    {
        public static readonly AuthenticateUserAsyncDelegate Default = PerformDefaultAuthentication;

        private async static Task PerformDefaultAuthentication(SshConnection connection, ILogger logger, SshClientSettings settings, CancellationToken ct)
        {
            // TODO: handle SSH_MSG_USERAUTH_BANNER.

            // Request ssh-userauth service
            using var serviceRequestMsg = CreateServiceRequestMessage(connection.SequencePool);
            await connection.SendPacketAsync(serviceRequestMsg.AsReadOnlySequence(), ct);
            using Sequence? serviceAcceptMsg = await connection.ReceivePacketAsync(ct);
            ParseServiceAccept(serviceAcceptMsg!);

            // Try credentials.
            foreach (var credential in settings.Credentials)
            {
                if (credential is PasswordCredential passwordCredential)
                {
                    logger.AuthenticationMethod("password");

                    using var userAuthMsg = CreateUserAuthRequestMessage(connection.SequencePool, passwordCredential.UserName, passwordCredential.Password);
                    await connection.SendPacketAsync(userAuthMsg.AsReadOnlySequence(), ct);
                }
                else
                {
                    throw new NotImplementedException("Unsupported credential type: " + credential.GetType().FullName);
                }

                // TODO...
                using Sequence? response = await connection.ReceivePacketAsync(ct);
                if (IsAuthSuccesfull(response!))
                {
                    logger.AuthenticationSucceeded();
                    return;
                }
            }

            throw new AuthenticationFailedException();
        }


        private static Sequence CreateServiceRequestMessage(SequencePool sequencePool)
        {
            using var writer = new SequenceWriter(sequencePool);
            writer.WriteByte(MessageNumber.SSH_MSG_SERVICE_REQUEST);
            writer.WriteString("ssh-userauth");
            return writer.BuildSequence();
        }

        private static void ParseServiceAccept(Sequence packet)
        {
            var reader = new SequenceReader(packet);
            reader.ReadByte(MessageNumber.SSH_MSG_SERVICE_ACCEPT);
            var reply = Encoding.UTF8.GetString(reader.ReadStringAsBytes().FirstSpan);
            reader.ReadEnd();
        }

        private static Sequence CreateUserAuthRequestMessage(SequencePool sequencePool, string userName, string password)
        {
            using var writer = new SequenceWriter(sequencePool);
            writer.WriteByte(MessageNumber.SSH_MSG_USERAUTH_REQUEST);
            writer.WriteString(userName);
            writer.WriteString("ssh-connection");
            writer.WriteString("password");
            writer.WriteBoolean(false);
            writer.WriteString(password);
            return writer.BuildSequence();
        }

        private static bool IsAuthSuccesfull(Sequence packet)
        {
            var reader = new SequenceReader(packet);
            byte b = reader.ReadByte();
            switch (b)
            {
                case MessageNumber.SSH_MSG_USERAUTH_SUCCESS:
                    return true;
                case MessageNumber.SSH_MSG_USERAUTH_FAILURE:
                    return false;
                default:
                    ThrowHelper.ThrowProtocolUnexpectedValue();
                    return false;
            }
        }
    }
}