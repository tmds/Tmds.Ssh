// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    // https://datatracker.ietf.org/doc/html/rfc4252 - Public Key Authentication Method: "publickey"
    sealed class PublicKeyAuth
    {
        public static async Task<bool> TryAuthenticate(PrivateKeyCredential keyCredential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger logger, CancellationToken ct)
        {
            if (!context.IsAuthenticationAllowed(AlgorithmNames.PublicKey))
            {
                return false;
            }

            string filename = keyCredential.FilePath;
            if (!File.Exists(filename))
            {
                return false;
            }

            if (PrivateKeyParser.TryParsePrivateKeyFile(keyCredential.FilePath, keyCredential.PasswordPrompt, out PrivateKey? pk, out Exception? error))
            {
                using (pk)
                {
                    if (pk is RsaPrivateKey rsaKey)
                    {
                        if (rsaKey.KeySize < context.MinimumRSAKeySize)
                        {
                            // TODO: log
                            return false;
                        }
                    }

                    foreach (var keyAlgorithm in pk.Algorithms)
                    {
                        if (!context.PublicKeyAcceptedAlgorithms.Contains(keyAlgorithm))
                        {
                            continue;
                        }

                        logger.AuthenticationMethodPublicKey(keyCredential.FilePath);
                        {
                            using var userAuthMsg = CreatePublicKeyRequestMessage(
                                keyAlgorithm, context.SequencePool, context.UserName, connectionInfo.SessionId!, pk!);
                            await context.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                        }

                        bool success = await context.ReceiveAuthIsSuccesfullAsync(ct).ConfigureAwait(false);
                        if (success)
                        {
                            return true;
                        }
                    }
                }
            }
            else
            {
                throw new PrivateKeyLoadException(filename, error);
            }

            return false;
        }

        private static Packet CreatePublicKeyRequestMessage(Name algorithm, SequencePool sequencePool, string userName, byte[] sessionId, PrivateKey privateKey)
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
            writer.WriteString(algorithm);
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
                signatureWriter.WriteString(algorithm);
                privateKey.AppendPublicKey(ref signatureWriter);
                privateKey.AppendSignature(algorithm, ref writer, signatureData.AsReadOnlySequence());
            }

            return packet.Move();
        }
    }
}