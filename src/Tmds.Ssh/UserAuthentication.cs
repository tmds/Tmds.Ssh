// This file is part of Tmds.Ssh which is released under LGPL-3.0.
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

                    using var userAuthMsg = CreatePasswordRequestMessage(connection.SequencePool,
                                                settings.UserName!, passwordCredential.Password);

                    await connection.SendPacketAsync(userAuthMsg.AsReadOnlySequence(), ct);
                }
                else if (credential is IdentityFileCredential ifCredential)
                {
                    if (IdentityFileCredential.TryParseFile(ifCredential.Filename, out PrivateKey? pk))
                    {
                        logger.AuthenticationMethodPublicKey(ifCredential.Filename);
                        using (pk)
                        {
                            using var userAuthMsg = CreatePublicKeyRequestMessage(connection.SequencePool,
                                                        settings.UserName!, connectionInfo.SessionId!, pk!);
                            await connection.SendPacketAsync(userAuthMsg.AsReadOnlySequence(), ct);
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
                using Sequence? response = await connection.ReceivePacketAsync(ct);
                if (IsAuthSuccesfull(response!))
                {
                    logger.AuthenticationSucceeded();
                    return;
                }
            }

            throw new AuthenticationFailedException();
        }

        private static Sequence CreatePublicKeyRequestMessage(SequencePool sequencePool, string userName, byte[] sessionId, PrivateKey privateKey)
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
            var writer = new SequenceWriter(sequencePool);
            writer.WriteByte(MessageNumber.SSH_MSG_USERAUTH_REQUEST);
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
                var signatureWriter = new SequenceWriter(sequencePool); // TODO: this doesn't have a using.
                signatureWriter.WriteString(sessionId);
                signatureWriter.WriteByte(MessageNumber.SSH_MSG_USERAUTH_REQUEST);
                signatureWriter.WriteString(userName);
                signatureWriter.WriteString("ssh-connection");
                signatureWriter.WriteString("publickey");
                signatureWriter.WriteBoolean(true);
                signatureWriter.WriteString(privateKey.Format);
                privateKey.AppendPublicKey(ref signatureWriter);
                using var signatureData = signatureWriter.BuildSequence();
                privateKey.AppendSignature(ref writer, signatureData.AsReadOnlySequence());
            }

            return writer.BuildSequence();;
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
            reader.SkipString();
            reader.ReadEnd();
        }

        private static Sequence CreatePasswordRequestMessage(SequencePool sequencePool, string userName, string password)
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