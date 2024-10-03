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

        int partialAuthAttempts = 0;
        // Try credentials.
        List<Credential> credentials = new(_settings.CredentialsOrDefault);
        for (int i = 0; i < credentials.Count; i++)
        {
            Credential credential = credentials[i];

            AuthResult authResult = AuthResult.Failure;
            bool? methodAccepted;
            Name method;
            if (credential is PasswordCredential passwordCredential)
            {
                if (TryMethod(AlgorithmNames.Password))
                {
                    authResult = await PasswordAuth.TryAuthenticate(passwordCredential, context, ConnectionInfo, Logger, ct).ConfigureAwait(false);
                }
            }
            else if (credential is PrivateKeyCredential keyCredential)
            {
                if (TryMethod(AlgorithmNames.PublicKey))
                {
                    authResult = await PublicKeyAuth.TryAuthenticate(keyCredential, context, ConnectionInfo, Logger, ct).ConfigureAwait(false);
                }
            }
            else if (credential is KerberosCredential kerberosCredential)
            {
                if (TryMethod(AlgorithmNames.GssApiWithMic))
                {
                    authResult = await GssApiAuth.TryAuthenticate(kerberosCredential, context, ConnectionInfo, Logger, ct).ConfigureAwait(false);
                }
            }
            else
            {
                throw new NotImplementedException("Unsupported credential type: " + credential.GetType().FullName);
            }

            // We didn't try the method, skip to the next credential.
            if (methodAccepted == false)
            {
                continue;
            }

            if (authResult == AuthResult.Success)
            {
                return;
            }

            if (authResult == AuthResult.Failure)
            {
                // If we didn't know if the method was accepted before, check the context which was updated by SSH_MSG_USERAUTH_FAILURE.
                if (methodAccepted == null)
                {
                    methodAccepted = context.IsMethodAccepted(method);
                }
                // Don't try a failed credential again if it matched an accepted method.
                if (methodAccepted == true || methodAccepted == null)
                {
                    credentials.RemoveAt(i);
                    i--;
                }
            }

            if (authResult == AuthResult.Partial)
            {
                // The same method may be requested multiple times with partial auth.
                // The client should be providing different credentials when the same method is tried again.
                // Move the current credential to the back of the list so we don't try it as the first one once more.
                credentials.RemoveAt(i);
                credentials.Add(credential);

                // Start over (but limit the amount of times we want to start over to avoid an infinite loop).
                if (++partialAuthAttempts == Constants.MaxPartialAuths)
                {
                    break;
                }
                else
                {
                    i = -1;
                }
            }

            bool TryMethod(Name credentialMethod)
            {
                method = credentialMethod;
                methodAccepted = context.IsMethodAccepted(method);
                return methodAccepted != false;
            }
        }

        throw new ConnectFailedException(ConnectFailedReason.AuthenticationFailed, "Authentication failed.", ConnectionInfo);
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
