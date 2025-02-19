using System.Buffers;
using System.Net.Security;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

static partial class SshClientLogger
{
    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Error,
        Message = "Could not connect to '{HostName}' port {Port}")]
    public static partial void CouldNotConnect(this ILogger<SshClient> logger, string hostName, int port, Exception exception);

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Information,
        EventName = nameof(HostConnect),
        Message = "Connecting to {EndPoint} for {Destination} via {Proxies}")]
    public static partial void HostConnectWithProxies(this ILogger<SshClient> logger, ConnectEndPoint endpoint, ConnectEndPoint destination, IEnumerable<Uri> proxies);

#pragma warning disable SYSLIB1025 // Multiple logging methods should not use the same event name within a class
    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Information,
        EventName = nameof(HostConnect),
        Message = "Connecting to {EndPoint}")]
#pragma warning restore SYSLIB1025 // Multiple logging methods should not use the same event name within a class
#pragma warning disable SYSLIB1015 // Argument is not referenced from the logging message
    // Include Destinations and Proxies in State, but not in message. Note, name of the arguments must match with those used in HostConnectWithProxies.Message.
    public static partial void HostConnectWithoutProxies(this ILogger<SshClient> logger, ConnectEndPoint EndPoint, ConnectEndPoint Destination, IEnumerable<Uri> Proxies);
#pragma warning restore SYSLIB1015 // Argument is not referenced from the logging message

    public static void HostConnect(this ILogger<SshClient> logger, ConnectEndPoint endpoint, ConnectEndPoint destination, IEnumerable<Uri> proxies)
    {
        if (destination == endpoint && !proxies.Any())
        {
            HostConnectWithoutProxies(logger, endpoint, destination, Proxies: []);
        }
        else
        {
            HostConnectWithProxies(logger, endpoint, destination, proxies.ToArray());
        }
    }

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Information,
        Message = "Connection established")]
    public static partial void ConnectionEstablished(this ILogger<SshClient> logger);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Information,
        Message = "Local version: '{IdentificationString}'")]
    public static partial void LocalVersion(this ILogger<SshClient> logger, string identificationString);

    [LoggerMessage(
        EventId = 4,
        Level = LogLevel.Information,
        Message = "Remote version: '{IdentificationString}'")]
    public static partial void RemoteVersion(this ILogger<SshClient> logger, string identificationString);

    [LoggerMessage(
        EventId = 5,
        Level = LogLevel.Information,
        Message =
        """
        Client Algorithms
        kex: {KeyExchangeAlgorithms}
        hostkey: {ServerHostKeyAlgorithms}
        cipher c2s: {EncryptionAlgorithmsClientToServer}
        cipher s2c: {EncryptionAlgorithmsServerToClient}
        mac c2s: {MacAlgorithmsClientToServer}
        mac s2s: {MacAlgorithmsServerToClient}
        compr c2s: {CompressionAlgorithmsClientToServer}
        compr s2c: {CompressionAlgorithmsServerToClient}
        lang c2s: {LanguagesClientToServer}
        lang s2c: {LanguagesServerToClient}
        """)]
    public static partial void ClientKexInit(this ILogger<SshClient> logger,
            List<Name> keyExchangeAlgorithms,
            List<Name> ServerHostKeyAlgorithms,
            List<Name> encryptionAlgorithmsClientToServer,
            List<Name> encryptionAlgorithmsServerToClient,
            List<Name> macAlgorithmsClientToServer,
            List<Name> macAlgorithmsServerToClient,
            List<Name> compressionAlgorithmsClientToServer,
            List<Name> compressionAlgorithmsServerToClient,
            List<Name> languagesClientToServer,
            List<Name> languagesServerToClient
        );

    [LoggerMessage(
        EventId = 6,
        Level = LogLevel.Information,
        Message =
        """
        Server Algorithms
        kex: {KeyExchangeAlgorithms}
        hostkey: {ServerHostKeyAlgorithms}
        cipher c2s: {EncryptionAlgorithmsClientToServer}
        cipher s2c: {EncryptionAlgorithmsServerToClient}
        mac c2s: {MacAlgorithmsClientToServer}
        mac s2s: {MacAlgorithmsServerToClient}
        compr c2s: {CompressionAlgorithmsClientToServer}
        compr s2c: {CompressionAlgorithmsServerToClient}
        lang c2s: {LanguagesClientToServer}
        lang s2c: {LanguagesServerToClient}
        first kex packet follows: {FirstKexPacketFollows}
        """)]
    public static partial void ServerKexInit(this ILogger<SshClient> logger,
            Name[] keyExchangeAlgorithms,
            Name[] ServerHostKeyAlgorithms,
            Name[] encryptionAlgorithmsClientToServer,
            Name[] encryptionAlgorithmsServerToClient,
            Name[] macAlgorithmsClientToServer,
            Name[] macAlgorithmsServerToClient,
            Name[] compressionAlgorithmsClientToServer,
            Name[] compressionAlgorithmsServerToClient,
            Name[] languagesClientToServer,
            Name[] languagesServerToClient,
            bool firstKexPacketFollows
        );

    [LoggerMessage(
        EventId = 7,
        Level = LogLevel.Information,
        Message =
        """
        Negotiated Algorithms
        kex: {KeyExchangeAlgorithms}
        hostkey: {ServerHostKeyAlgorithms}
        cipher c2s: {EncryptionAlgorithmClientToServer}
        cipher s2c: {EncryptionAlgorithmServerToClient}
        mac c2s: {MacAlgorithmClientToServer}
        mac s2s: {MacAlgorithmServerToClient}
        compr c2s: {CompressionAlgorithmClientToServer}
        compr s2c: {CompressionAlgorithmServerToClient}
        """)]
    public static partial void KexAlgorithms(this ILogger<SshClient> logger,
            List<Name> keyExchangeAlgorithms,
            List<Name> ServerHostKeyAlgorithms,
            string encryptionAlgorithmClientToServer,
            string encryptionAlgorithmServerToClient,
            string macAlgorithmClientToServer,
            string macAlgorithmServerToClient,
            string compressionAlgorithmClientToServer,
            string compressionAlgorithmServerToClient
        );

    [LoggerMessage(
        EventId = 8,
        Level = LogLevel.Information,
        Message = "Exchanging keys using {Algorithm}")]
    public static partial void ExchangingKeys(this ILogger<SshClient> logger, string algorithm);

    [LoggerMessage(
        EventId = 9,
        Level = LogLevel.Information,
        Message = "Key exchange completed")]
    public static partial void KeyExchangeCompleted(this ILogger<SshClient> logger);

    [LoggerMessage(
        EventId = 10,
        Level = LogLevel.Information,
        Message = "Host '{HostName}' is known and matches {Type} SHA256:{SHA256Fingerprint} key")]
    public static partial void ServerKeyIsKnownHost(this ILogger<SshClient> logger, string hostname, string type, string sha256Fingerprint);

    [LoggerMessage(
        EventId = 11,
        Level = LogLevel.Information,
        Message = "Server key {Type} SHA256:{SHA256Fingerprint} is approved")]
    public static partial void ServerKeyIsApproved(this ILogger<SshClient> logger, string type, string sha256Fingerprint);

    [LoggerMessage(
        EventId = 12,
        Level = LogLevel.Information,
        Message = "Adding {Type} key SHA256:{SHA256Fingerprint} for '{HostName}' to '{KnownHostsFilePath}'")]
    public static partial void ServerKeyAddKnownHost(this ILogger<SshClient> logger, string hostname, string type, string sha256Fingerprint, string knownHostsFilePath);

    [LoggerMessage(
        EventId = 13,
        Level = LogLevel.Information,
        Message = "Loading known host keys from '{KnownHostsFilePath}'")]
    public static partial void LoadingKnownHostKeys(this ILogger<SshClient> logger, string knownHostsFilePath);

    [LoggerMessage(
        EventId = 14,
        Level = LogLevel.Information,
        Message = "Can not load known host keys from '{KnownHostsFilePath}': \"{Message}\"")]
    public static partial void CanNotReadKnownHostKeys(this ILogger<SshClient> logger, string knownHostsFilePath, string message);

    [LoggerMessage(
        EventId = 15,
        Level = LogLevel.Information,
        Message = "Authenticating to '{HostName}' as '{UserName}'")]
    public static partial void Authenticating(this ILogger<SshClient> logger, string hostName, string userName);

    [LoggerMessage(
        EventId = 16,
        Level = LogLevel.Information,
        Message = "Authenticated succesfully using {AuthMethod}")]
    public static partial void Authenticated(this ILogger<SshClient> logger, string authMethod);

    [LoggerMessage(
        EventId = 17,
        Level = LogLevel.Information,
        Message = "Auth using password")]
    public static partial void PasswordAuth(this ILogger<SshClient> logger);

    [LoggerMessage(
        EventId = 18,
        Level = LogLevel.Information,
        Message = "Auth using gssapi-with-mic for '{TargetName}' as '{KerberosPrincipal}' (delegation: {Delegation})")]
    public static partial void GssApiWithMicAuth(this ILogger<SshClient> logger, string kerberosPrincipal, string targetName, bool delegation);

    [LoggerMessage(
        EventId = 19,
        Level = LogLevel.Information,
        Message = "Auth using publickey '{keyIdentifier}' with {SignatureAlgorithm} signature")]
    public static partial void PublicKeyAuth(this ILogger<SshClient> logger, string keyIdentifier, string signatureAlgorithm);

    [LoggerMessage(
        EventId = 20,
        Level = LogLevel.Information,
        Message = "GSS-API negotiate failed with {Status}")]
    public static partial void GssApiWithMicFail(this ILogger<SshClient> logger, NegotiateAuthenticationStatusCode status);

    [LoggerMessage(
        EventId = 21,
        Level = LogLevel.Information,
        Message = "Auth {AuthMethod} method failed, continue with: {AllowedMethods}")]
    public static partial void AuthMethodFailed(this ILogger<SshClient> logger, string authMethod, Name[] allowedMethods);

    [LoggerMessage(
        EventId = 22,
        Level = LogLevel.Information,
        Message = "Private key '{KeyIdentifier}' not found")]
    public static partial void PrivateKeyNotFound(this ILogger<SshClient> logger, string keyIdentifier);

    [LoggerMessage(
        EventId = 23,
        Level = LogLevel.Error,
        Message = "Failed to load private key '{KeyIdentifier}'")]
    public static partial void PrivateKeyCanNotLoad(this ILogger<SshClient> logger, string keyIdentifier, Exception exception);

    [LoggerMessage(
        EventId = 24,
        Level = LogLevel.Information,
        Message = "Private key '{KeyIdentifier}' has no accepted algorithms. Accepted host algorithms: {AcceptedHostAlgorithms}. Accepted signature algorithms: {AcceptedSignatureAlgorithms}")]
    public static partial void PrivateKeyAlgorithmsNotAccepted(this ILogger<SshClient> logger, string keyIdentifier, IReadOnlyCollection<Name>? acceptedHostAlgorithms, IReadOnlyCollection<Name>? acceptedSignatureAlgorithms);

    [LoggerMessage(
        EventId = 25,
        Level = LogLevel.Trace,
        Message = "Received {MessageId} {Payload}")]
    private static partial void PacketReceived(this ILogger<SshClient> logger, MessageId? messageId, PacketPayload payload);

    public static void PacketReceived(this ILogger<SshClient> logger, ReadOnlyPacket packet)
        => PacketReceived(logger, packet.MessageId, new PacketPayload(packet));

    [LoggerMessage(
        EventId = 26,
        Level = LogLevel.Trace,
        Message = "Sending {MessageId} {Payload}")]
    private static partial void PacketSend(this ILogger<SshClient> logger, MessageId? messageId, PacketPayload payload);

    public static void PacketSend(this ILogger<SshClient> logger, ReadOnlyPacket packet)
        => PacketSend(logger, packet.MessageId, new PacketPayload(packet));

    [LoggerMessage(
        EventId = 27,
        Level = LogLevel.Information,
        Message = "Connection closed by client")]
    public static partial void ClientClosedConnection(this ILogger<SshClient> logger);

    [LoggerMessage(
        EventId = 28,
        Level = LogLevel.Error,
        Message = "Connection aborted")]
    public static partial void ConnectionAborted(this ILogger<SshClient> logger, Exception exception);

    [LoggerMessage(
        EventId = 29,
        Level = LogLevel.Information,
        Message = "Auth {AuthMethod} method partial success, continue with: {AllowedMethods}")]
    public static partial void PartialSuccessAuth(this ILogger<SshClient> logger, string authMethod, Name[] allowedMethods);

    [LoggerMessage(
        EventId = 30,
        Level = LogLevel.Information,
        Message = "Auth using none")]
    public static partial void NoneAuth(this ILogger<SshClient> logger);

    [LoggerMessage(
        EventId = 31,
        Level = LogLevel.Error,
        Message = "Private key '{KeyIdentifier}' failed to sign with {Algorithm}")]
    public static partial void PrivateKeyFailedToSign(this ILogger<SshClient> logger, string keyIdentifier, string algorithm, Exception exception);

    [LoggerMessage(
        EventId = 32,
        Level = LogLevel.Error,
        Message = "Private key '{KeyIdentifier}' does not meet minimal key length")]
    public static partial void PrivateKeyDoesNotMeetMinimalKeyLength(this ILogger<SshClient> logger, string keyIdentifier);

    [LoggerMessage(
        EventId = 33,
        Level = LogLevel.Error,
        Message = "Failed to connect to SSH Agent")]
    public static partial void CannotConnectToSshAgent(this ILogger<SshClient> logger, Exception exception);

    [LoggerMessage(
        EventId = 34,
        Level = LogLevel.Information,
        Message = "Proxying at {ProxyUri} to {ProxyTarget} for {Destination}")]
    public static partial void Proxy(this ILogger<SshClient> logger, Uri proxyUri, ConnectEndPoint proxyTarget, ConnectEndPoint destination);

    [LoggerMessage(
        EventId = 35,
        Level = LogLevel.Information,
        Message = "Certificate '{Identifier}' not found")]
    public static partial void ClientCertificateNotFound(this ILogger<SshClient> logger, string identifier);

    [LoggerMessage(
        EventId = 36,
        Level = LogLevel.Error,
        Message = "Failed to load certificate '{Identifier}'")]
    public static partial void ClientCertificateCanNotLoad(this ILogger<SshClient> logger, string identifier, Exception exception);

    [LoggerMessage(
        EventId = 37,
        Level = LogLevel.Error,
        Message = "Certificate '{CertificateIdentifier}' does not match private key '{KeyIdentifier}'")]
    public static partial void ClientCertificatePrivateKeyMismatch(this ILogger<SshClient> logger, string certificateIdentifier, string keyIdentifier);

    [LoggerMessage(
        EventId = 38,
        Level = LogLevel.Information,
        Message =
        """
        Server Extension Negotiation
        keysig: {KeySignatureAlgorithms}
        """)]
    public static partial void ServerExtensionNegotiation(this ILogger<SshClient> logger,
            Name[]? keySignatureAlgorithms
        );

    [LoggerMessage(
        EventId = 39,
        Level = LogLevel.Error,
        Message = "Failed to find key for certificate '{CertificateIdentifier}'. Identities checked: {IdentitiesCount}, SSH Agent keys checked: {SshAgentKeyCount}")]
    public static partial void CertificateFileKeyNotFound(this ILogger<SshClient> logger, string certificateIdentifier, int identitiesCount, int? sshAgentKeyCount);

    struct PacketPayload // TODO: implement ISpanFormattable
    {
        private static readonly int MaxDataLength = 2 * PrettyBytePrinter.BytesPerLine;

        static PacketPayload()
        {
            string? value = Environment.GetEnvironmentVariable("TMDS_SSH_TRACE_DATA_LENGTH");
            if (!string.IsNullOrEmpty(value) && long.TryParse(value, out long l))
            {
                if (l == -1)
                {
                    l = int.MaxValue;
                }
                l = Math.Max(PrettyBytePrinter.BytesPerLine, l);
                MaxDataLength = (int)Math.Min(int.MaxValue, l);
            }
        }

        private ReadOnlyPacket _packet;
        public PacketPayload(ReadOnlyPacket packet)
        {
            _packet = packet;
        }

        public override string ToString()
        {
            ReadOnlySequence<byte> payload = _packet.Payload;
            bool trimmed = false;
            if ((_packet.MessageId == MessageId.SSH_MSG_CHANNEL_DATA ||
                _packet.MessageId == MessageId.SSH_MSG_CHANNEL_EXTENDED_DATA
                ) && (payload.Length > MaxDataLength))
            {
                payload = payload.Slice(0, MaxDataLength);
                trimmed = true;
            }
            return PrettyBytePrinter.ToMultiLineString(payload) +
                (trimmed ? $"{Environment.NewLine}..." : "");
        }
    }
}