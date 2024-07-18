// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

internal delegate Task AuthenticateUserAsyncDelegate(SshConnection connection, string userName, IReadOnlyList<Credential> credentials, List<Name> publicKeyAcceptedAlgorithms, int minimumRSAKeySize, SshConnectionInfo connectionInfo, ILogger logger, CancellationToken token);

// Authentication Protocol: https://tools.ietf.org/html/rfc4252.
sealed partial class UserAuthentication
{
    public static readonly AuthenticateUserAsyncDelegate Default = PerformDefaultAuthentication;

    private async static Task PerformDefaultAuthentication(SshConnection connection, string userName, IReadOnlyList<Credential> credentials, List<Name> publicKeyAcceptedAlgorithms, int minimumRSAKeySize, SshConnectionInfo connectionInfo, ILogger logger, CancellationToken ct)
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

        UserAuthContext context = new UserAuthContext(connection, userName, publicKeyAcceptedAlgorithms, minimumRSAKeySize, logger);

        bool authSuccess = false;

        // gssapi-with-mic may require interaction with the ticket server.
        // Before doing that, we first send a send a "none" credential to get the list of accepted auth methods.
        // This list is tracked by the UserAuthContext and enables us to skip gssapi-with-mic when the server does not allow it.
        Credential? firstCredential = credentials.Count > 0 ? credentials[0] : null;
        bool authWithNone = firstCredential is KerberosCredential;
        if (authWithNone)
        {
            authSuccess = await None.TryAuthenticate(context, connectionInfo, logger, ct).ConfigureAwait(false);

            if (authSuccess)
            {
                return;
            }
        }

        // Try credentials.
        foreach (var credential in credentials)
        {
            if (credential is PasswordCredential passwordCredential)
            {
                authSuccess = await PasswordAuth.TryAuthenticate(passwordCredential, context, connectionInfo, logger, ct).ConfigureAwait(false);
            }
            else if (credential is PrivateKeyCredential keyCredential)
            {
                authSuccess = await PublicKeyAuth.TryAuthenticate(keyCredential, context, connectionInfo, logger, ct).ConfigureAwait(false);
            }
            else if (credential is KerberosCredential kerberosCredential)
            {
                authSuccess = await GssApiAuth.TryAuthenticate(kerberosCredential, context, connectionInfo, logger, ct).ConfigureAwait(false);
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

        throw new ConnectFailedException(ConnectFailedReason.AuthenticationFailed, "Authentication failed.", connectionInfo);
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
}
