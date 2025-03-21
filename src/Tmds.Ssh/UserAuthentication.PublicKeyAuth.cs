// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    // https://datatracker.ietf.org/doc/html/rfc4252 - Public Key Authentication Method: "publickey"
    public sealed class PublicKeyAuth
    {
        private const MessageId SSH_MSG_USERAUTH_PK_OK = (MessageId)60;

        public static async Task<AuthResult> TryAuthenticate(PrivateKeyCredential keyCredential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            string keyIdentifier = keyCredential.Identifier;
            PrivateKeyCredential.Key key;
            try
            {
                key = await keyCredential.LoadKeyAsync(ct).ConfigureAwait(false);
                if (key.PrivateKey is null)
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

            using (key.PrivateKey)
            {
                result = await DoAuthAsync(keyIdentifier, key.PrivateKey, key.QueryKey, context, context.SupportedAcceptedPublicKeyAlgorithms, connectionInfo, logger, ct).ConfigureAwait(false);
            }

            return result;
        }

        private static bool MeetsMinimumRSAKeySize(PrivateKey privateKey, int minimumRSAKeySize)
        {
            if (privateKey is RsaPrivateKey rsaKey)
            {
                return rsaKey.KeySize >= minimumRSAKeySize;
            }
            else
            {
                RsaPublicKey publicKey = RsaPublicKey.CreateFromSshKey(privateKey.PublicKey.RawData);
                return publicKey.KeySize >= minimumRSAKeySize;
            }
        }

        public static ValueTask<AuthResult> DoAuthAsync(string keyIdentifier, PrivateKey pk, bool queryKey, UserAuthContext context, IReadOnlyCollection<Name>? acceptedHostKeyAlgorithms, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
            => DoAuthAsync(keyIdentifier, pk, pk.PublicKey, queryKey, context, acceptedHostKeyAlgorithms, connectionInfo, logger, ct);

        public static async ValueTask<AuthResult> DoAuthAsync(string keyIdentifier, PrivateKey pk, SshKeyData clientKey, bool queryKey, UserAuthContext context, IReadOnlyCollection<Name>? acceptedHostKeyAlgorithms, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            if (context.IsSkipPublicAuthKey(clientKey))
            {
                return AuthResult.Skipped;
            }

            if (pk.PublicKey.Type == AlgorithmNames.SshRsa && !MeetsMinimumRSAKeySize(pk, context.MinimumRSAKeySize))
            {
                logger.PrivateKeyDoesNotMeetMinimalKeyLength(keyIdentifier);

                context.AddPublicAuthKeyToSkip(clientKey);

                return AuthResult.Skipped;
            }

            AuthResult result = AuthResult.Skipped;

            bool acceptedAnyAlgorithm = false;
            foreach (var signAlgorithm in pk.Algorithms)
            {
                if (context.AcceptedPublicKeySignatureAlgorithms?.Contains(signAlgorithm) == false)
                {
                    continue;
                }
                Name pubkeyAlgorithm = AlgorithmNames.GetHostKeyAlgorithmForSignatureAlgorithm(clientKey.Type, signAlgorithm);
                if (acceptedHostKeyAlgorithms?.Contains(pubkeyAlgorithm) == false)
                {
                    continue;
                }
                acceptedAnyAlgorithm = true;

                context.StartAuth(AlgorithmNames.PublicKey);
                logger.PublicKeyAuth(keyIdentifier, pubkeyAlgorithm);

                // Check if the server accepts the key before making a signing attempt.
                // This is to avoid interactive prompts for unlocking keys that don't match the target server.
                if (queryKey)
                {
                    {
                        using var queryKeyMsg = CreatePublicKeyRequestMessage(pubkeyAlgorithm, context.SequencePool, context.UserName, connectionInfo.SessionId!, clientKey.RawData, signature: null);
                        await context.SendPacketAsync(queryKeyMsg.Move(), ct).ConfigureAwait(false);
                    }
                    using Packet response = await context.ReceivePacketAsync(ct).ConfigureAwait(false);
                    MessageId messageId = response.MessageId!.Value;
                    if (messageId == MessageId.SSH_MSG_USERAUTH_FAILURE)
                    {
                        return context.AuthResult;
                    }
                    else
                    {
                        SequenceReader reader = response.GetReader();
                        reader.ReadMessageId(SSH_MSG_USERAUTH_PK_OK);
                        reader.ReadName(pubkeyAlgorithm);
                        SshKeyData key = reader.ReadSshKey();
                        if (!key.Equals(clientKey))
                        {
                            ThrowHelper.ThrowDataUnexpectedValue();
                        }
                    }
                }

                byte[] data = CreateDataForSigning(pubkeyAlgorithm, context.UserName, connectionInfo.SessionId!, clientKey.RawData);
                byte[] signature;
                try
                {
                    signature = await pk.SignAsync(signAlgorithm, data, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    logger.PrivateKeyFailedToSign(keyIdentifier, signAlgorithm, ex);
                    return AuthResult.Failure;
                }

                {
                    using var userAuthMsg = CreatePublicKeyRequestMessage(
                            pubkeyAlgorithm, context.SequencePool, context.UserName, connectionInfo.SessionId!, clientKey.RawData, signature);
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
                logger.PrivateKeyAlgorithmsNotAccepted(keyIdentifier, acceptedHostKeyAlgorithms, context.AcceptedPublicKeySignatureAlgorithms);
            }

            context.AddPublicAuthKeyToSkip(clientKey);

            return result;
        }

        private static byte[] CreateDataForSigning(Name algorithm, string userName, byte[] sessionId, ReadOnlyMemory<byte> publicKey)
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

        private static Packet CreatePublicKeyRequestMessage(Name algorithm, SequencePool sequencePool, string userName, byte[] sessionId, ReadOnlyMemory<byte> publicKey, byte[]? signature)
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
            writer.WriteBoolean(signature is not null);
            writer.WriteString(algorithm);
            writer.WriteString(publicKey);
            if (signature is not null)
            {
                writer.WriteString(signature);
            }
            return packet.Move();
        }
    }
}