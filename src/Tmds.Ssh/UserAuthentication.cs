// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    internal delegate Task AuthenticateUserAsyncDelegate(SshConnection connection, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken token);

    // Authentication Protocol: https://tools.ietf.org/html/rfc4252.
    sealed class UserAuthentication
    {
        public static readonly AuthenticateUserAsyncDelegate Default = PerformDefaultAuthentication;

        private async static Task PerformDefaultAuthentication(SshConnection connection, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct)
        {
            // TODO: handle SSH_MSG_USERAUTH_BANNER.

            // Request ssh-userauth service
            {
                using var serviceRequestMsg = CreateServiceRequestMessage(connection.SequencePool);
                await connection.SendPacketAsync(serviceRequestMsg.Move(), ct);
            }
            {
                using Packet serviceAcceptMsg = await connection.ReceivePacketAsync(ct);
                ParseServiceAccept(serviceAcceptMsg);
            }

            // Try credentials.
            foreach (var credential in settings.Credentials)
            {
                if (credential is PasswordCredential passwordCredential)
                {
                    logger.AuthenticationMethod("password");

                    using var userAuthMsg = CreatePasswordRequestMessage(connection.SequencePool,
                                                settings.UserName, passwordCredential.Password);
                    await connection.SendPacketAsync(userAuthMsg.Move(), ct);
                }
                else if (credential is IdentityFileCredential ifCredential)
                {
                    if (IdentityFileCredential.TryParseFile(ifCredential.Filename, out PrivateKey? pk))
                    {

                        using (pk)
                        {
                            logger.AuthenticationMethodPublicKey(ifCredential.Filename);

                            using var userAuthMsg = CreatePublicKeyRequestMessage(connection.SequencePool,
                                                        settings.UserName, connectionInfo.SessionId!, pk!);
                            await connection.SendPacketAsync(userAuthMsg.Move(), ct);
                        }
                    }
                    else
                    {
                        continue;
                    }
                }
                else
                {
                    throw new NotImplementedException("Unsupported credential type: " + credential.GetType().FullName);
                }

                // TODO...
                using Packet response = await connection.ReceivePacketAsync(ct);
                if (IsAuthSuccesfull(response))
                {
                    logger.AuthenticationSucceeded();
                    return;
                }
            }

            throw new AuthenticationFailedException();
        }

        private static Packet CreatePublicKeyRequestMessage(SequencePool sequencePool, string userName, byte[] sessionId, PrivateKey privateKey)
        {
            /*
                byte      SSH_MSG_USERAUTH_REQUEST
                string    user name
                string    service name
                string    "publickey"
                boolean   TRUE
                string    public key algorithm name
                string    public key to be used for authentication
                string    signature
             */
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
            writer.WriteString(userName);
            writer.WriteString("ssh-connection");
            writer.WriteString("publickey");
            writer.WriteBoolean(true);
            writer.WriteString(privateKey.Format);
            privateKey.AppendPublicKey(ref writer);
            {
                /*
                    string    session identifier
                    byte      SSH_MSG_USERAUTH_REQUEST
                    string    user name
                    string    service name
                    string    "publickey"
                    boolean   TRUE
                    string    public key algorithm name
                    string    public key to be used for authentication
                 */
                using var signatureData = sequencePool.RentSequence();
                var signatureWriter = new SequenceWriter(signatureData);
                signatureWriter.WriteString(sessionId);
                signatureWriter.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
                signatureWriter.WriteString(userName);
                signatureWriter.WriteString("ssh-connection");
                signatureWriter.WriteString("publickey");
                signatureWriter.WriteBoolean(true);
                signatureWriter.WriteString(privateKey.Format);
                privateKey.AppendPublicKey(ref signatureWriter);
                privateKey.AppendSignature(ref writer, signatureData.AsReadOnlySequence());
            }

            return packet.Move();
        }

        private static Packet CreateServiceRequestMessage(SequencePool sequencePool)
        {
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(MessageId.SSH_MSG_SERVICE_REQUEST);
            writer.WriteString("ssh-userauth");
            return packet.Move();
        }

        private static void ParseServiceAccept(ReadOnlyPacket packet)
        {
            var reader = packet.GetReader();
            reader.ReadMessageId(MessageId.SSH_MSG_SERVICE_ACCEPT);
            reader.SkipString();
            reader.ReadEnd();
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

        private static bool IsAuthSuccesfull(ReadOnlyPacket packet)
        {
            var reader = packet.GetReader();
            MessageId b = reader.ReadMessageId();
            switch (b)
            {
                case MessageId.SSH_MSG_USERAUTH_SUCCESS:
                    return true;
                case MessageId.SSH_MSG_USERAUTH_FAILURE:
                    return false;
                default:
                    ThrowHelper.ThrowProtocolUnexpectedValue();
                    return false;
            }
        }
    }
}