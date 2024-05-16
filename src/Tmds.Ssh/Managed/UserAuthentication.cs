// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh.Managed
{
    internal delegate Task AuthenticateUserAsyncDelegate(SshConnection connection, ILogger logger, ManagedSshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken token);

    // Authentication Protocol: https://tools.ietf.org/html/rfc4252.
    sealed partial class UserAuthentication
    {
        public static readonly AuthenticateUserAsyncDelegate Default = PerformDefaultAuthentication;

        private async static Task PerformDefaultAuthentication(SshConnection connection, ILogger logger, ManagedSshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct)
        {
            // Request ssh-userauth service
            {
                using var serviceRequestMsg = CreateServiceRequestMessage(connection.SequencePool);
                await connection.SendPacketAsync(serviceRequestMsg.Move(), ct).ConfigureAwait(false);
            }
            {
                using Packet serviceAcceptMsg = await connection.ReceivePacketAsync(ct).ConfigureAwait(false);
                ParseServiceAccept(serviceAcceptMsg);
            }

            // Try credentials.
            foreach (var credential in settings.Credentials)
            {
                if (credential is PasswordCredential passwordCredential)
                {
                    logger.AuthenticationMethod("password");

                    string? password = passwordCredential.GetPassword();
                    if (password is not null)
                    {
                        using var userAuthMsg = CreatePasswordRequestMessage(connection.SequencePool,
                                                    settings.UserName, password);
                        await connection.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                    }
                }
                else if (credential is PrivateKeyCredential ifCredential)
                {
                    if (TryParsePrivateKeyFile(ifCredential.FilePath, out PrivateKey? pk))
                    {
                        using (pk)
                        {
                            logger.AuthenticationMethodPublicKey(ifCredential.FilePath);

                            using var userAuthMsg = CreatePublicKeyRequestMessage(connection.SequencePool,
                                                        settings.UserName, connectionInfo.SessionId!, pk!);
                            await connection.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                        }
                    }
                    else
                    {
                        continue; // TODO: report issues with parsing the private key.
                    }
                }
                else
                {
                    throw new NotImplementedException("Unsupported credential type: " + credential.GetType().FullName);
                }

                /*
                    The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
                    time after this authentication protocol starts and before
                    authentication is successful.
                */
                bool is_banner;
                do
                {
                    using Packet response = await connection.ReceivePacketAsync(ct).ConfigureAwait(false);

                    // TODO: return banner to the user.
                    is_banner = response.MessageId == MessageId.SSH_MSG_USERAUTH_BANNER;

                    if (!is_banner)
                    {
                        if (IsAuthSuccesfull(response))
                        {
                            logger.AuthenticationSucceeded();
                            return;
                        }
                    }
                } while (is_banner);
            }

            throw new ConnectFailedException(ConnectFailedReason.AuthenticationFailed, "Authentication failed.", connectionInfo);
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