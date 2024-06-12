// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Reflection;
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

    private readonly Func<string?> _getPassword;
    private readonly bool _delegateCredential;
    private readonly string? _serviceName;

#if NET8_0
    private delegate void GetMICDelegate(ReadOnlySpan<byte> data, IBufferWriter<byte> writer);

    private static readonly Lazy<MethodInfo?> _getMicMethInfo = new Lazy<MethodInfo?>(() =>
        typeof(NegotiateAuthentication).GetMethod("GetMIC", BindingFlags.NonPublic | BindingFlags.Instance));

    private MethodInfo GetMICMethod { get; }
#endif

    /// <summary>
    /// Create a GSSAPI user authentication context with password string.
    /// </summary>
    /// <param name="password">The password to use for the GSSAPI username. Set to null to use a cached credential.</param>
    /// <param name="delegateCredential">Request delegation on the GSSAPI context.</param>
    /// <param name="serviceName">Override the service principal name (SPN), default it to use the connection hostname</param>
    public GssapiWithMicCredential(string? password = null, bool delegateCredential = false, string? serviceName = null) : this(() => password, delegateCredential, serviceName)
    { }

    /// <summary>
    /// Create a GSSAPI user authentication context with a password prompt.
    /// </summary>
    /// <param name="passwordPrompt">A prompting function that is called to retrieve the password when needed.</param>
    /// <param name="delegateCredential">Request delegation on the GSSAPI context.</param>
    /// <param name="serviceName">Override the service principal name (SPN), default it to use the connection hostname</param>
    public GssapiWithMicCredential(Func<string?> passwordPrompt, bool delegateCredential = false, string? serviceName = null)
    {
        _getPassword = passwordPrompt;
        _delegateCredential = delegateCredential;
        _serviceName = serviceName;

#if NET8_0
        GetMICMethod = _getMicMethInfo.Value ?? throw new InvalidOperationException("Failed to find GetMIC method needed for .NET 8.0.");
#endif
    }

    internal async Task<bool> TryAuthenticate(SshConnection connection, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct)
    {
        string spn = _serviceName ?? $"host@{connectionInfo.Host}";
        logger.AuthenticationMethodGssapiWithMic(settings.UserName, spn, _delegateCredential);

        bool isOidSuccess = await TryStageOid(connection, settings.UserName, ct).ConfigureAwait(false);
        if (!isOidSuccess)
        {
            return false;
        }

        var negotiateOptions = new NegotiateAuthenticationClientOptions()
        {
            AllowedImpersonationLevel = _delegateCredential ? TokenImpersonationLevel.Delegation : TokenImpersonationLevel.Impersonation,
            Package = "Kerberos",
            RequiredProtectionLevel = ProtectionLevel.Sign,
            // While RFC states this should be set to "false", Win32-OpenSSH
            // fails if it's not true. I'm unsure if openssh-portable on Linux
            // will fail in the same way or not.
            RequireMutualAuthentication = true,
            TargetName = spn,
        };

        string? password = _getPassword();
        if (password is not null)
        {
            negotiateOptions.Credential = new NetworkCredential(settings.UserName, password);
        }

        using var authContext = new NegotiateAuthentication(negotiateOptions);
        bool isAuthSuccess = await TryStageAuthentication(connection, authContext, ct).ConfigureAwait(false);
        if (!isAuthSuccess)
        {
            return false;
        }

        {
            using var message = authContext.IsSigned
                ? CreateGssapiMicData(connection.SequencePool, connectionInfo.SessionId!, settings.UserName, authContext)
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
        GetMICMethod.CreateDelegate<GetMICDelegate>(authContext)(
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
