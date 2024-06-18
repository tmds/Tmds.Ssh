// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

public sealed class KerberosCredential : Credential
{
    // gssapi-with-mic is defined in https://datatracker.ietf.org/doc/html/rfc4462
    private const string AUTH_METHOD = "gssapi-with-mic";

    // Kerberos - 1.2.840.113554.1.2.2 - This is DER encoding of the OID.
    private static readonly byte[] KRB5_OID = [ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02 ];

    private readonly NetworkCredential _kerberosCredential;
    private readonly bool _delegateCredential;
    private readonly string? _serviceName;

#if NET8_0
    // This API was made public in .NET 9 through ComputeIntegrityCheck.
    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "GetMIC")]
    private extern static void GetMICMethod(NegotiateAuthentication context, ReadOnlySpan<byte> data, IBufferWriter<byte> writer);
#endif

    /// <summary>
    /// Create a credential for Kerberos authentication.
    /// </summary>
    /// <remarks>
    /// The credential specified is used for the Kerberos authentication process. This can either be the same or
    /// different from the username specified through <c>SshClientSettings.UserName</c>. The client settings username
    /// is the target login user the SSH service is meant to run as, whereas the credential is the Kerberos
    /// principal used for authentication. The rules for how a Kerberos principal maps to the target user is defined by
    /// the SSH service itself. For example on Windows the username should be the same but on Linux the mapping can be
    /// done through a <c>.k5login</c> file in the target user's home directory.
    ///
    /// If the credential is <c>null<c>, the Kerberos authentication will be done using a cached ticket.
    /// For Windows, this is the current thread's identity (typically logon user) will be used.
    /// For Unix/Linux, this will use the Kerberos credential cache principal, which may be managed using the
    /// <c>kinit</c> command. If there is no available cache credential, the authentication will fail.
    ///
    /// Credentials can only be delegated if the Kerberos ticket retrieved from the KDC is marked as forwardable.
    /// Windows hosts will always retrieve a forwardable ticket but non-Windows hosts may not. When using an explicit
    /// credential, make sure that 'forwardable = true' is set in the krb5.conf file so that .NET will request a
    /// forwardable ticket required for delegation. When using a cached ticket, make sure that when the ticket was
    /// retrieved it was retrieved with the forwardable flag. If the ticket is not forwardable, the authentication will
    /// still work but the ticket will not be delegated.
    /// </remarks>
    /// <param name="credential">The credentials to use for the Kerberos authentication exchange. Set to null to use a cached ticket.</param>
    /// <param name="delegateCredential">Allows the SSH server to delegate the user on remote systems.</param>
    /// <param name="serviceName">Override the service principal name (SPN), default uses the <c>host/<SshClientSettings.Host>.</c></param>
    public KerberosCredential(NetworkCredential? credential = null, bool delegateCredential = false, string? serviceName = null)
    {
        if (!string.IsNullOrWhiteSpace(credential?.UserName) && string.IsNullOrWhiteSpace(credential?.Password))
        {
            throw new ArgumentException("credential Password cannot be null or an empty string.", nameof(credential));
        }
        _kerberosCredential = credential ?? CredentialCache.DefaultNetworkCredentials;
        _delegateCredential = delegateCredential;
        _serviceName = serviceName;
    }

    internal async Task<bool> TryAuthenticate(SshConnection connection, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct)
    {
        // RFC uses hostbased SPN format "service@host" but Windows SSPI needs the service/host format.
        // .NET converts this format to the hostbased format expected by GSSAPI for us.
        string spn = string.IsNullOrEmpty(_serviceName) ? $"host/{connectionInfo.Host}" : _serviceName;

        // The SSH messages must have a username value which maps to the target user we want to login as. We use the
        // client supplied username as the target user. The Kerberos principal credential is only used for the
        // authentication stage that happens next.
        string userName = settings.UserName;
        logger.AuthenticationMethodGssapiWithMic(userName, _kerberosCredential.UserName, spn, _delegateCredential);

        bool isOidSuccess = await TryStageOid(connection, logger, userName, ct).ConfigureAwait(false);
        if (!isOidSuccess)
        {
            return false;
        }

        var negotiateOptions = new NegotiateAuthenticationClientOptions()
        {
            AllowedImpersonationLevel = _delegateCredential ? TokenImpersonationLevel.Delegation : TokenImpersonationLevel.Impersonation,
            Credential = _kerberosCredential,
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
            TargetName = spn,
        };

        using var authContext = new NegotiateAuthentication(negotiateOptions);
        bool isAuthSuccess = await TryStageAuthentication(connection, logger, authContext, ct).ConfigureAwait(false);
        if (!isAuthSuccess)
        {
            return false;
        }

        try
        {
            // While we request signing, the server may not so we need to check to see if we need to send a MIC.
            using var message = authContext.IsSigned
                ? CreateGssapiMicData(connection.SequencePool, connectionInfo.SessionId!,  userName, authContext)
                : CreateGssapiCompleteMessage(connection.SequencePool);
            await connection.SendPacketAsync(message.Move(), ct).ConfigureAwait(false);
        }
        catch (MissingMethodException)
        {
            // Remove once .NET 8 is no longer the minimum and we get rid of reflection.
            return false;
        }

        return true;
    }

    private static async Task<bool> TryStageOid(SshConnection connection, ILogger logger, string userName, CancellationToken ct)
    {
        {
            using var userAuthMsg = CreateOidRequestMessage(connection.SequencePool,
                                        userName, KRB5_OID);
            await connection.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
        }

        while (true)
        {
            using Packet response = await connection.ReceivePacketAsync(ct).ConfigureAwait(false);
            MessageId? mid = response.MessageId;

            if (mid == MessageId.SSH_MSG_USERAUTH_BANNER)
            {
                // First message in exchange could be a banner which we ignore
                // for now.
                continue;
            }

            if (mid == MessageId.SSH_MSG_USERAUTH_FAILURE)
            {
                logger.AuthenticationKerberosFailed("No OID response received");
                return false;
            }
            else if (mid != MessageId.SSH_MSG_USERAUTH_GSSAPI_RESPONSE)
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

    private static async Task<bool> TryStageAuthentication(SshConnection connection, ILogger logger, NegotiateAuthentication authContext, CancellationToken ct)
    {
        byte[]? outToken = authContext.GetOutgoingBlob(Array.Empty<byte>(), out var statusCode);

        while (outToken is not null)
        {
            {
                using var userAuthMsg = CreateGssapiTokenMessage(connection.SequencePool, outToken);
                await connection.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
            }

            // Only continue the exchange if we need more tokens.
            if (statusCode != NegotiateAuthenticationStatusCode.ContinueNeeded)
            {
                break;
            }

            // If not complete we expect the response input token to continue the auth.
            using Packet response = await connection.ReceivePacketAsync(ct).ConfigureAwait(false);
            ReadOnlySequence<byte>? tokenResponse = GetGssapiTokenResponse(response);
            if (tokenResponse is null)
            {
                break;
            }

            outToken = authContext.GetOutgoingBlob(
                tokenResponse.Value.IsSingleSegment ? tokenResponse.Value.FirstSpan : tokenResponse.Value.ToArray(),
                out statusCode);
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
        writer.WriteString(AUTH_METHOD);
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

    private static Packet CreateGssapiMicData(SequencePool sequencePool, ReadOnlySpan<byte> sessionId, string userName, NegotiateAuthentication authContext)
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
        writer.WriteString(AUTH_METHOD);
        ReadOnlySequence<byte> micData = sequence.AsReadOnlySequence();

        var signatureWriter = new ArrayBufferWriter<byte>();

#if NET8_0
        GetMICMethod(
            authContext,
            micData.IsSingleSegment ? micData.FirstSpan : micData.ToArray(),
            signatureWriter);
#else
        authContext.ComputeIntegrityCheck(
            micData.IsSingleSegment ? micData.FirstSpan : micData.ToArray(),
            signatureWriter);
#endif

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
