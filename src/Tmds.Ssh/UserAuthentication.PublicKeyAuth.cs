// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    // https://datatracker.ietf.org/doc/html/rfc4252 - Public Key Authentication Method: "publickey"
    public sealed class PublicKeyAuth
    {
        public static async Task<AuthResult> TryAuthenticate(PrivateKeyCredential keyCredential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            PrivateKey? pk;
            try
            {
                pk = await keyCredential.LoadKeyAsync(ct);
                if (pk is null)
                {
                    logger.PrivateKeyNotFound(keyCredential.Identifier);
                    return AuthResult.Skipped;
                }
            }
            catch (Exception error)
            {
                logger.PrivateKeyCanNotLoad(keyCredential.Identifier, error);
                return AuthResult.Skipped;
            }

            using (pk)
            {
                if (pk is RsaPrivateKey rsaKey)
                {
                    if (rsaKey.KeySize < context.MinimumRSAKeySize)
                    {
                        // TODO: log
                        return AuthResult.Skipped;
                    }
                }

                bool acceptedAlgorithm = false;
                foreach (var keyAlgorithm in pk.Algorithms)
                {
                    if (!context.PublicKeyAcceptedAlgorithms.Contains(keyAlgorithm))
                    {
                        continue;
                    }

                    context.StartAuth(AlgorithmNames.PublicKey);

                    acceptedAlgorithm = true;
                    logger.PublicKeyAuth(keyCredential.Identifier, keyAlgorithm);

                    {
                        using var userAuthMsg = CreatePublicKeyRequestMessage(
                            keyAlgorithm, context.SequencePool, context.UserName, connectionInfo.SessionId!, pk!);
                        await context.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                    }

                    AuthResult result = await context.ReceiveAuthResultAsync(ct).ConfigureAwait(false);
                    if (result != AuthResult.Failure)
                    {
                        return result;
                    }
                }

                if (!acceptedAlgorithm)
                {
                    logger.PrivateKeyAlgorithmsNotAccepted(keyCredential.Identifier, context.PublicKeyAcceptedAlgorithms);
                    return AuthResult.Skipped;
                }
            }

            return AuthResult.Failure;
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