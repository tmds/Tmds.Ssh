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

public sealed class GssapiWithMicCredential : Credential
{
    // gssapi-with-mic is defined in https://datatracker.ietf.org/doc/html/rfc4462
    private const string AUTH_METHOD = "gssapi-with-mic";

    // Kerberos - 1.2.840.113554.1.2.2
    private static readonly byte[] KRB5_OID = [ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02 ];

    private readonly NetworkCredential _credential;
    private readonly bool _delegateCredential;
    private readonly string? _serviceName;

#if NET8_0
    // This API was made public in .NET 9 through ComputeIntegrityCheck.
    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "GetMIC")]
    private extern static void GetMICMethod(NegotiateAuthentication context, ReadOnlySpan<byte> data, IBufferWriter<byte> writer);
#endif

    /// <summary>
    /// Create a GSSAPI user authentication context.
    /// </summary>
    /// <remarks>
    /// If the credential is null, CredentialCache.DefaultNetworkCredentials is used, or the username is an empty
    /// string, the SSH connection string username is the one sent to the SSH server as the login user. The GSSAPI
    /// authentication stage will not use the connection string username but will rely on the cached credential for
    /// your environment.
    ///
    /// Credentials can only be delegated if the Kerberos ticket retrieved from the KDC is marked as forwardable.
    /// Windows hosts will always retrieve a forwardable ticket but non-Windows hosts may not. When using an explicit
    /// credential, make sure that 'forwardable = true' is set in the krb5.conf file. When using a cached credential
    /// make sure that when the ticket was retrieved it was retrieved with the forwardable flag. If the ticket is not
    /// forwardable, the authentication will still work but the ticket will not be delegated.
    /// </remarks>
    /// <param name="credential">The credentials to use for the GSSAPI authentication exchange. Set to null to use the cached credential.</param>
    /// <param name="delegateCredential">Request delegation on the GSSAPI context.</param>
    /// <param name="serviceName">Override the service principal name (SPN), default uses the <c>host/{connection.HostName}.</c></param>
    public GssapiWithMicCredential(NetworkCredential? credential = null, bool delegateCredential = false, string? serviceName = null)
    {
        _credential = credential ?? CredentialCache.DefaultNetworkCredentials;
        _delegateCredential = delegateCredential;
        _serviceName = serviceName;
    }

    internal async Task<bool> TryAuthenticate(SshConnection connection, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct)
    {
        // RFC uses hostbased SPN format "service@host" but Windows SSPI needs the service/host format.
        // The latter works on both SSPI and GSSAPI so we use that as the default.
        string spn = string.IsNullOrEmpty(_serviceName) ? $"host/{connectionInfo.Host}" : _serviceName;

        // The SSH messages must have a username value. If the credential provided is null or empty then use the
        // username from the connection settings as the target user to login with. The GSSAPI authentication token
        // will continue to use the cached credential for the environment for authentication though.
        string userName = string.IsNullOrEmpty(_credential.UserName) ? settings.UserName : _credential.UserName;
        logger.AuthenticationMethodGssapiWithMic(userName, spn, _delegateCredential);

        bool isOidSuccess = await TryStageOid(connection, userName, ct).ConfigureAwait(false);
        if (!isOidSuccess)
        {
            return false;
        }

        var negotiateOptions = new NegotiateAuthenticationClientOptions()
        {
            AllowedImpersonationLevel = _delegateCredential ? TokenImpersonationLevel.Delegation : TokenImpersonationLevel.Impersonation,
            Credential = _credential,
            Package = "Kerberos",
            // While only Sign is needed we need to set EncryptAndSign for
            // Windows client support. Sign only will pass in SECQOP_WRAP_NO_ENCRYPT
            // to MakeSignature which fails.
            RequiredProtectionLevel = ProtectionLevel.EncryptAndSign,
            // While RFC states this should be set to "false", Win32-OpenSSH
            // fails if it's not true. I'm unsure if openssh-portable on Linux
            // will fail in the same way or not.
            RequireMutualAuthentication = true,
            TargetName = spn,
        };

        using var authContext = new NegotiateAuthentication(negotiateOptions);
        bool isAuthSuccess = await TryStageAuthentication(connection, authContext, ct).ConfigureAwait(false);
        if (!isAuthSuccess)
        {
            return false;
        }

        {
            using var message = authContext.IsSigned
                ? CreateGssapiMicData(connection.SequencePool, connectionInfo.SessionId!,  userName, authContext)
                : CreateGssapiCompleteMessage(connection.SequencePool);
            await connection.SendPacketAsync(message.Move(), ct).ConfigureAwait(false);
        }

        return true;
    }

    private async Task<bool> TryStageOid(SshConnection connection, string userName, CancellationToken ct)
    {
        {
            using var userAuthMsg = CreateOidRequestMessage(connection.SequencePool,
                                        userName, KRB5_OID);
            await connection.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
        }

        using Packet response = await connection.ReceivePacketAsync(ct).ConfigureAwait(false);
        ReadOnlySequence<byte>? oidResponse = GetGssapiOidResponse(response);

        if (oidResponse is null)
        {
            return false;
        }

        return KRB5_OID.AsSpan().SequenceEqual(
            oidResponse.Value.IsSingleSegment ? oidResponse.Value.FirstSpan : oidResponse.Value.ToArray());
    }

    private async Task<bool> TryStageAuthentication(SshConnection connection, NegotiateAuthentication authContext, CancellationToken ct)
    {
        byte[]? outToken = authContext.GetOutgoingBlob(Array.Empty<byte>(), out var statusCode);
        while (outToken is not null)
        {
            {
                using var userAuthMsg = CreateGssapiTokenMessage(connection.SequencePool, outToken);
                await connection.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
            }

            // If the context is complete we don't expect a response.
            if (statusCode == NegotiateAuthenticationStatusCode.Completed)
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

        return statusCode == NegotiateAuthenticationStatusCode.Completed;
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

    private Packet CreateGssapiMicData(SequencePool sequencePool, ReadOnlySpan<byte> sessionId, string userName, NegotiateAuthentication authContext)
    {
        /*
            string    session identifier
            byte      SSH_MSG_USERAUTH_REQUEST
            string    user name
            string    service
            string    "gssapi-with-mic"
        */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteString(sessionId);
        writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
        writer.WriteString(userName);
        writer.WriteString("ssh-connection");
        writer.WriteString(AUTH_METHOD);

        // The MIC data does not include the header, so skip the first 5 bytes.
        ReadOnlySequence<byte> micData = packet.Move().AsReadOnlySequence().Slice(5);

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

    private static ReadOnlySequence<byte>? GetGssapiOidResponse(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        MessageId b = reader.ReadMessageId();
        switch (b)
        {
            case MessageId.SSH_MSG_USERAUTH_GSSAPI_RESPONSE:
                return reader.ReadStringAsBytes();
            case MessageId.SSH_MSG_USERAUTH_FAILURE:
                return null;
            default:
                ThrowHelper.ThrowProtocolUnexpectedValue();
                return null;
        }
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
