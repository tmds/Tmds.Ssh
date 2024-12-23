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
            string keyIdentifier = keyCredential.Identifier;
            PrivateKey? pk;
            try
            {
                pk = await keyCredential.LoadKeyAsync(ct);
                if (pk is null)
                {
                    logger.PrivateKeyNotFound(keyIdentifier);
                    return AuthResult.Skipped;
                }
            }
            catch (Exception error)
            {
                logger.PrivateKeyCanNotLoad(keyIdentifier, error);
                return AuthResult.Skipped;
            }

            AuthResult result;

            using (pk)
            {
                result = await DoAuthAsync(keyIdentifier, pk, context, context.SupportedAcceptedPublicKeyAlgorithms, connectionInfo, logger, ct).ConfigureAwait(false);
            }

            return result;
        }

        private static bool MeetsMinimumRSAKeySize(PrivateKey privateKey, int minimumRSAKeySize)
        {
            if (privateKey is RsaPrivateKey rsaKey)
            {
                return rsaKey.KeySize >= minimumRSAKeySize;
            }
            else if (privateKey is SshAgentPrivateKey)
            {
                RsaPublicKey publicKey = RsaPublicKey.CreateFromSshKey(privateKey.PublicKey.Data);
                return publicKey.KeySize >= minimumRSAKeySize;
            }
            else
            {
                throw new NotSupportedException($"Unexpected PrivateKey type: {privateKey.GetType().FullName}");
            }
        }

        public static async ValueTask<AuthResult> DoAuthAsync(string keyIdentifier, PrivateKey pk, UserAuthContext context, IReadOnlyCollection<Name>? acceptedAlgorithms, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            if (context.IsSkipPublicAuthKey(pk.PublicKey))
            {
                return AuthResult.Skipped;
            }

            if (pk.PublicKey.Type == AlgorithmNames.SshRsa && !MeetsMinimumRSAKeySize(pk, context.MinimumRSAKeySize))
            {
                // TODO: log

                context.AddPublicAuthKeyToSkip(pk.PublicKey);

                return AuthResult.Skipped;
            }

            AuthResult result = AuthResult.Skipped;

            bool acceptedAnyAlgorithm = false;
            bool signingFailed = false;
            foreach (var signAlgorithm in pk.Algorithms)
            {
                if (acceptedAlgorithms is not null && !acceptedAlgorithms.Contains(signAlgorithm))
                {
                    continue;
                }

                byte[] data = CreateDataForSigning(signAlgorithm, context.UserName, connectionInfo.SessionId!, pk.PublicKey.Data);
                byte[]? signature = await pk.TrySignAsync(signAlgorithm, data, ct);
                if (signature is null)
                {
                    // TODO: log
                    signingFailed = true;
                    continue;
                }

                context.StartAuth(AlgorithmNames.PublicKey);
                logger.PublicKeyAuth(keyIdentifier, signAlgorithm);

                acceptedAnyAlgorithm = true;
                {
                    using var userAuthMsg = CreatePublicKeyRequestMessage(
                            signAlgorithm, context.SequencePool, context.UserName, connectionInfo.SessionId!, pk.PublicKey.Data, signature);
                    await context.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                }

                result = await context.ReceiveAuthResultAsync(ct).ConfigureAwait(false);
                if (result is AuthResult.Success or AuthResult.Partial or AuthResult.FailureMethodNotAllowed)
                {
                    return result;
                }
                Debug.Assert(result is AuthResult.Failure);
            }

            if (!acceptedAnyAlgorithm)
            {
                logger.PrivateKeyAlgorithmsNotAccepted(keyIdentifier, acceptedAlgorithms!);
            }

            context.AddPublicAuthKeyToSkip(pk.PublicKey);

            return result;
        }

        private static byte[] CreateDataForSigning(Name algorithm, string userName, byte[] sessionId, byte[] publicKey)
        {
            using var dataWriter = new ArrayWriter();
            dataWriter.WriteString(sessionId);
            dataWriter.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
            dataWriter.WriteString(userName);
            dataWriter.WriteString("ssh-connection");
            dataWriter.WriteString("publickey");
            dataWriter.WriteBoolean(true);
            dataWriter.WriteString(algorithm);
            dataWriter.WriteString(publicKey);
            return dataWriter.ToArray();
        }

        private static Packet CreatePublicKeyRequestMessage(Name algorithm, SequencePool sequencePool, string userName, byte[] sessionId, byte[] publicKey, byte[] signature)
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
            writer.WriteString(publicKey);
            writer.WriteString(signature);
            return packet.Move();
        }
    }
}