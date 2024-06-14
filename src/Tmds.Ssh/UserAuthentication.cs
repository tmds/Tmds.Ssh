// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

internal delegate Task AuthenticateUserAsyncDelegate(SshConnection connection, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken token);

// Authentication Protocol: https://tools.ietf.org/html/rfc4252.
sealed partial class UserAuthentication
{
    public static readonly AuthenticateUserAsyncDelegate Default = PerformDefaultAuthentication;

    private async static Task PerformDefaultAuthentication(SshConnection connection, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct)
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
                    {
                        using var userAuthMsg = CreatePasswordRequestMessage(connection.SequencePool,
                                                    settings.UserName, password);
                        await connection.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                    }
                    bool isAuthSuccesfull = await ReceiveAuthIsSuccesfullAsync(connection, logger, ct).ConfigureAwait(false);
                    if (isAuthSuccesfull)
                    {
                        return;
                    }
                }
            }
            else if (credential is PrivateKeyCredential ifCredential)
            {
                string filename = ifCredential.FilePath;
                if (!File.Exists(filename))
                {
                    continue;
                }

                if (TryParsePrivateKeyFile(ifCredential.FilePath, out PrivateKey? pk, out Exception? error))
                {
                    using (pk)
                    {
                        foreach (var keyAlgorithm in pk.Algorithms)
                        {
                            logger.AuthenticationMethodPublicKey(ifCredential.FilePath);

                            {
                                using var userAuthMsg = CreatePublicKeyRequestMessage(keyAlgorithm, connection.SequencePool,
                                                            settings.UserName, connectionInfo.SessionId!, pk!);
                                await connection.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                            }

                            bool isAuthSuccesfull = await ReceiveAuthIsSuccesfullAsync(connection, logger, ct).ConfigureAwait(false);
                            if (isAuthSuccesfull)
                            {
                                return;
                            }
                        }
                    }
                }
                else
                {
                    throw new PrivateKeyLoadException(filename, error);
                }
            }
            else if (credential is KerberosCredential kerberosCredential)
            {
                bool isKerberosSuccessful = await kerberosCredential.TryAuthenticate(connection, logger, settings, connectionInfo, ct).ConfigureAwait(false);
                if (!isKerberosSuccessful)
                {
                    continue;
                }

                bool isAuthSuccesfull = await ReceiveAuthIsSuccesfullAsync(connection, logger, ct).ConfigureAwait(false);
                if (isAuthSuccesfull)
                {
                    return;
                }
            }
            else
            {
                throw new NotImplementedException("Unsupported credential type: " + credential.GetType().FullName);
            }
        }

        throw new ConnectFailedException(ConnectFailedReason.AuthenticationFailed, "Authentication failed.", connectionInfo);
    }

    private async static Task<bool> ReceiveAuthIsSuccesfullAsync(SshConnection connection, ILogger logger, CancellationToken ct)
    {
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
                bool isSuccess = IsAuthSuccesfull(response);
                if (isSuccess)
                {
                    logger.AuthenticationSucceeded();
                }
                return isSuccess;
            }
        } while (true);
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
