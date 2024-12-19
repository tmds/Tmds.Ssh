// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    public sealed class SshAgentAuth
    {
        public static async Task<AuthResult> TryAuthenticate(SshAgentCredentials credential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            EndPoint? endPoint = SshAgent.DefaultEndPoint;
            if (endPoint is null)
            {
                return AuthResult.Skipped;
            }

            using var sshAgent = new SshAgent(endPoint, context.SequencePool);

            if (!await sshAgent.TryConnect(ct))
            {
                return AuthResult.Skipped;
            }

            List<SshAgent.Identity> keys = await sshAgent.RequestIdentitiesAsync(ct);
            if (keys.Count == 0)
            {
                return AuthResult.Skipped;
            }

            bool acceptedAlgorithm = false;
            foreach (var key in keys)
            {
                if (context.IsSkipPublicAuthKey(key.PublicKey))
                {
                    continue;
                }

                SequenceReader reader = new SequenceReader(key.PublicKey);
                Name keyType = reader.ReadName();

                Name[] algorithms = PublicKey.AlgorithmsForKeyType(ref keyType).ToArray();

                foreach (var signAlgorithm in algorithms)
                {
                    if (!context.PublicKeyAcceptedAlgorithms.Contains(signAlgorithm))
                    {
                        continue;
                    }

                    byte[] data = CreateDataForSigning(signAlgorithm, context.SequencePool, context.UserName, connectionInfo.SessionId!, key.PublicKey);
                    byte[]? signature = await sshAgent.TrySignAsync(signAlgorithm, key.PublicKey, data, ct);
                    if (signature is null)
                    {
                        continue;
                    }

                    context.StartAuth(AlgorithmNames.PublicKey);
                    acceptedAlgorithm = true;

                    string keyIdentifier = key.Comment;
                    logger.PublicKeyAuth(keyIdentifier, signAlgorithm);

                    {
                        using var userAuthMsg = CreatePublicKeyRequestMessage(
                            signAlgorithm, context.SequencePool, context.UserName, connectionInfo.SessionId!, key.PublicKey, signature);
                        await context.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                    }

                    AuthResult result = await context.ReceiveAuthResultAsync(ct).ConfigureAwait(false);
                    if (result != AuthResult.Failure)
                    {
                        return result;
                    }
                }

                if (acceptedAlgorithm)
                {
                    context.AddPublicAuthKeyToSkip(key.PublicKey);
                }
            }

            if (!acceptedAlgorithm)
            {
                logger.PrivateKeyAlgorithmsNotAccepted(keyIdentifier: "ssh-agent", context.PublicKeyAcceptedAlgorithms);
                return AuthResult.Skipped;
            }

            return AuthResult.Failure;
        }

        private static byte[] CreateDataForSigning(Name algorithm, SequencePool sequencePool, string userName, byte[] sessionId, byte[] publicKey)
        {
            using var data = sequencePool.RentSequence();
            var dataWriter = new SequenceWriter(data);
            dataWriter.WriteString(sessionId);
            dataWriter.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
            dataWriter.WriteString(userName);
            dataWriter.WriteString("ssh-connection");
            dataWriter.WriteString("publickey");
            dataWriter.WriteBoolean(true);
            dataWriter.WriteString(algorithm);
            dataWriter.WriteString(publicKey);
            return data.AsReadOnlySequence().ToArray();
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