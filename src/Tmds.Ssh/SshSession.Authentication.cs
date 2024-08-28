// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using static Tmds.Ssh.UserAuthentication;

namespace Tmds.Ssh;

sealed partial class SshSession
{
    private async Task AuthenticateAsync(SshConnection connection, CancellationToken ct)
    {
        Debug.Assert(_settings is not null);

        Logger.Authenticating(ConnectionInfo.HostName, _settings.UserName);

        // Request ssh-userauth service
        {
            using var serviceRequestMsg = CreateServiceRequestMessage(connection.SequencePool);
            await connection.SendPacketAsync(serviceRequestMsg.Move(), ct).ConfigureAwait(false);
        }
        {
            using Packet serviceAcceptMsg = await connection.ReceivePacketAsync(ct).ConfigureAwait(false);
            ParseServiceAccept(serviceAcceptMsg);
        }

        UserAuthContext context = new UserAuthContext(connection, _settings.UserName, _settings.PublicKeyAcceptedAlgorithms, _settings.MinimumRSAKeySize, Logger);

        bool authSuccess;

        // Try credentials.
        foreach (var credential in _settings.Credentials)
        {
            if (credential is PasswordCredential passwordCredential)
            {
                authSuccess = await PasswordAuth.TryAuthenticate(passwordCredential, context, ConnectionInfo, Logger, ct).ConfigureAwait(false);
            }
            else if (credential is PrivateKeyCredential keyCredential)
            {
                authSuccess = await PublicKeyAuth.TryAuthenticate(keyCredential, context, ConnectionInfo, Logger, ct).ConfigureAwait(false);
            }
            else if (credential is KerberosCredential kerberosCredential)
            {
                authSuccess = await GssApiAuth.TryAuthenticate(kerberosCredential, context, ConnectionInfo, Logger, ct).ConfigureAwait(false);
            }
            else
            {
                throw new NotImplementedException("Unsupported credential type: " + credential.GetType().FullName);
            }

            if (authSuccess)
            {
                return;
            }
        }

        throw new ConnectFailedException(ConnectFailedReason.AuthenticationFailed, "Authentication failed.", ConnectionInfo);
    }

    private static Name GetAuthenticationMethod(Credential credential)
        => credential switch
        {
            PasswordCredential => AlgorithmNames.Password,
            PrivateKeyCredential => AlgorithmNames.PublicKey,
            KerberosCredential => AlgorithmNames.GssApiWithMic,
            _ => throw new NotImplementedException("Unsupported credential type: " + credential.GetType().FullName)
        };

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
}
