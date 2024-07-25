// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Net;
using System.Net.Security;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    // https://datatracker.ietf.org/doc/html/rfc4462 - GSS-API User Authentication
    sealed class GssApiAuth
    {
        // Kerberos - 1.2.840.113554.1.2.2 - This is DER encoding of the OID.
        private static readonly byte[] KRB5_OID = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];

        public static async Task<bool> TryAuthenticate(KerberosCredential credential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger logger, CancellationToken ct)
        {
            if (!context.IsAuthenticationAllowed(AlgorithmNames.GssApiWithMic))
            {
                return false;
            }

            // RFC uses hostbased SPN format "service@host" but Windows SSPI needs the service/host format.
            // .NET converts this format to the hostbased format expected by GSSAPI for us.
            string targetName = !string.IsNullOrEmpty(credential.TargetName) ? credential.TargetName : $"host@{connectionInfo.HostName}";
            NetworkCredential networkCredential = credential.NetworkCredential ?? CredentialCache.DefaultNetworkCredentials;

            // The SSH messages must have a username value which maps to the target user we want to login as. We use the
            // client supplied username as the target user. The Kerberos principal credential is only used for the
            // authentication stage that happens next.
            logger.AuthenticationMethodGssapiWithMic(context.UserName, networkCredential.UserName, targetName, credential.DelegateCredential);

            bool isOidSuccess = await TryStageOid(context, logger, context.UserName, ct).ConfigureAwait(false);
            if (!isOidSuccess)
            {
                return false;
            }

            var negotiateOptions = new NegotiateAuthenticationClientOptions()
            {
                AllowedImpersonationLevel = credential.DelegateCredential ? TokenImpersonationLevel.Delegation : TokenImpersonationLevel.Impersonation,
                Credential = networkCredential,
                Package = "Kerberos",
                // While only Sign is needed we need to set EncryptAndSign for
                // Windows client support. Sign only will pass in SECQOP_WRAP_NO_ENCRYPT
                // to MakeSignature which fails.
                // https://github.com/dotnet/runtime/issues/103461
                RequiredProtectionLevel = ProtectionLevel.EncryptAndSign,
                // While RFC states this should be set to "false", Win32-OpenSSH
                // fails if it's not true. I'm unsure if openssh-portable on Linux
                // will fail in the same way or not.
                RequireMutualAuthentication = true,
                TargetName = targetName
            };

            using var authContext = new AsyncNegotiateAuthentication(negotiateOptions);
            bool isAuthSuccess = await TryStageAuthentication(context, logger, authContext, ct).ConfigureAwait(false);
            if (!isAuthSuccess)
            {
                return false;
            }

            try
            {
                // While we request signing, the server may not so we need to check to see if we need to send a MIC.
                using var message = authContext.IsSigned
                    ? CreateGssapiMicData(context.SequencePool, connectionInfo.SessionId!, context.UserName, authContext)
                    : CreateGssapiCompleteMessage(context.SequencePool);
                await context.SendPacketAsync(message.Move(), ct).ConfigureAwait(false);
            }
            catch (MissingMethodException)
            {
                // Remove once .NET 8 is no longer the minimum and we get rid of reflection.
                return false;
            }

            return await context.ReceiveAuthIsSuccesfullAsync(ct).ConfigureAwait(false);
        }

        private static async Task<bool> TryStageOid(UserAuthContext context, ILogger logger, string userName, CancellationToken ct)
        {
            {
                using var userAuthMsg = CreateOidRequestMessage(context.SequencePool,
                                            userName, KRB5_OID);
                await context.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
            }

            while (true)
            {
                using Packet response = await context.ReceivePacketAsync(ct).ConfigureAwait(false);
                MessageId messageId = response.MessageId!.Value;

                if (messageId == MessageId.SSH_MSG_USERAUTH_FAILURE)
                {
                    logger.AuthenticationKerberosFailed("No OID response received");
                    return false;
                }
                else if (messageId != MessageId.SSH_MSG_USERAUTH_GSSAPI_RESPONSE)
                {
                    ThrowHelper.ThrowProtocolUnexpectedValue();
                }

                ReadOnlySequence<byte> oidResponse = GetGssapiOidResponse(response);
                if (KRB5_OID.AsSpan().SequenceEqual(oidResponse.IsSingleSegment ? oidResponse.FirstSpan : oidResponse.ToArray()))
                {
                    return true;
                }
                else
                {
                    string receivedOid = Convert.ToBase64String(oidResponse.IsSingleSegment ? oidResponse.FirstSpan : oidResponse.ToArray());
                    logger.AuthenticationKerberosFailed($"OID response {receivedOid} did not match expected value");
                    return false;
                }
            }
        }

        private static async Task<bool> TryStageAuthentication(UserAuthContext context, ILogger logger, AsyncNegotiateAuthentication authContext, CancellationToken ct)
        {
            (byte[]? outToken, NegotiateAuthenticationStatusCode statusCode) = await authContext.GetOutgoingBlobAsync(Array.Empty<byte>(), ct);

            while (outToken is not null)
            {
                {
                    using var userAuthMsg = CreateGssapiTokenMessage(context.SequencePool, outToken);
                    await context.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                }

                // Only continue the exchange if we need more tokens.
                if (statusCode != NegotiateAuthenticationStatusCode.ContinueNeeded)
                {
                    break;
                }

                // If not complete we expect the response input token to continue the auth.
                using Packet response = await context.ReceivePacketAsync(ct).ConfigureAwait(false);
                ReadOnlySequence<byte>? tokenResponse = GetGssapiTokenResponse(response);
                if (tokenResponse is null)
                {
                    break;
                }

                (outToken, statusCode) = await authContext.GetOutgoingBlobAsync(tokenResponse.Value.ToArray(), ct);
            }

            if (statusCode == NegotiateAuthenticationStatusCode.Completed)
            {
                return true;
            }
            else
            {
                logger.AuthenticationKerberosFailed($"Kerberos authentication failed with status {statusCode}");
                return false;
            }
        }

        private static Packet CreateOidRequestMessage(SequencePool sequencePool, string userName, ReadOnlySpan<byte> oid)
        {
            /*
                byte      SSH_MSG_USERAUTH_REQUEST
                string    user name (in ISO-10646 UTF-8 encoding)
                string    service name (in US-ASCII)
                string    "gssapi-with-mic" (US-ASCII method name)
                uint32    n, the number of mechanism OIDs client supports
                string[n] mechanism OIDs
            */
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
            writer.WriteString(userName);
            writer.WriteString("ssh-connection");
            writer.WriteString("gssapi-with-mic");
            writer.WriteUInt32(1);
            writer.WriteString(oid);
            return packet.Move();
        }

        private static Packet CreateGssapiTokenMessage(SequencePool sequencePool, ReadOnlySpan<byte> token)
        {
            /*
                byte        SSH_MSG_USERAUTH_GSSAPI_TOKEN
                string      data returned from either GSS_Init_sec_context()
                            or GSS_Accept_sec_context()
            */
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_GSSAPI_TOKEN);
            writer.WriteString(token);
            return packet.Move();
        }

        private static Packet CreateGssapiCompleteMessage(SequencePool sequencePool)
        {
            /*
                byte      SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE
            */
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE);
            return packet.Move();
        }

        private static Packet CreateGssapiMicData(SequencePool sequencePool, ReadOnlySpan<byte> sessionId, string userName, AsyncNegotiateAuthentication authContext)
        {
            /*
                string    session identifier
                byte      SSH_MSG_USERAUTH_REQUEST
                string    user name
                string    service
                string    "gssapi-with-mic"
            */
            // The MIC data does not include the header, so we don't need a Packet.
            using var sequence = sequencePool.RentSequence();
            var writer = new SequenceWriter(sequence);
            writer.WriteString(sessionId);
            writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
            writer.WriteString(userName);
            writer.WriteString("ssh-connection");
            writer.WriteString("gssapi-with-mic");
            ReadOnlySequence<byte> micData = sequence.AsReadOnlySequence();

            var signatureWriter = new ArrayBufferWriter<byte>();

        authContext.ComputeIntegrityCheck(
            micData.IsSingleSegment ? micData.FirstSpan : micData.ToArray(),
            signatureWriter);

            /*
                byte      SSH_MSG_USERAUTH_GSSAPI_MIC
                string    MIC
            */
            using var micPacket = sequencePool.RentPacket();
            var micWriter = micPacket.GetWriter();
            micWriter.WriteMessageId(MessageId.SSH_MSG_USERAUTH_GSSAPI_MIC);
            micWriter.WriteString(signatureWriter.WrittenSpan);
            return micPacket.Move();
        }

        private static ReadOnlySequence<byte> GetGssapiOidResponse(ReadOnlyPacket packet)
        {
            var reader = packet.GetReader();
            reader.ReadMessageId();
            return reader.ReadStringAsBytes();
        }

        private static ReadOnlySequence<byte>? GetGssapiTokenResponse(ReadOnlyPacket packet)
        {
            var reader = packet.GetReader();
            MessageId b = reader.ReadMessageId();
            switch (b)
            {
                case MessageId.SSH_MSG_USERAUTH_GSSAPI_TOKEN:
                    return reader.ReadStringAsBytes();
                case MessageId.SSH_MSG_USERAUTH_FAILURE:
                    return null;
                default:
                    ThrowHelper.ThrowProtocolUnexpectedValue();
                    return null;
            }
        }
    }
}