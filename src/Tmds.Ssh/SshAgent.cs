// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh
{
    // https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent - SSH Agent Protocol
    sealed class SshAgent : IDisposable
    {
        private const MessageId SSH_AGENTC_REQUEST_IDENTITIES = (MessageId)11;
        private const MessageId SSH_AGENTC_SIGN_REQUEST = (MessageId)13;
        private const MessageId SSH_AGENTC_EXTENSION = (MessageId)27;
        private const MessageId SSH_AGENT_FAILURE = (MessageId)5;
        private const MessageId SSH_AGENT_SUCCESS = (MessageId)6;
        private const MessageId SSH_AGENT_IDENTITIES_ANSWER = (MessageId)12;
        private const MessageId SSH_AGENT_SIGN_RESPONSE = (MessageId)14;
        private const string SessionBindExtension = "session-bind@openssh.com";
        private const uint SSH_AGENT_RSA_SHA2_256 = 2;
        private const uint SSH_AGENT_RSA_SHA2_512 = 4;
        private const int MaxPacketSize = int.MaxValue; // We trust the SSH Agent.

        public struct Identity
        {
            public string Comment { init; get; }
            public SshKeyData PublicKey { init; get; }
        }

        public static string? DefaultAddress
        {
            get
            {
                string? defaultAddress = OperatingSystem.IsWindows()
                    ? @"\\pipe\.\openssh-ssh-agent"
                    : null;
                string? authSock = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
                return string.IsNullOrEmpty(authSock) ? defaultAddress : authSock;
            }
        }

        private readonly string _address;
        private readonly SequencePool _sequencePool;
        private readonly ILogger<SshClient> _logger;

        private StreamSshConnection? _agentConnection;

        public SshAgent(string address, SequencePool sequencePool, ILogger<SshClient> logger)
        {
            _address = address;
            _sequencePool = sequencePool;
            _logger = logger;
        }

        // When 'bindSession' is set, the connection is bound to the session (see TryBindSessionAsync).
        public async ValueTask ConnectAsync(SshConnectionInfo? bindSession, CancellationToken cancellationToken)
        {
            Stream? stream = null;
            try
            {
                stream = await OpenStreamAsync(_address, cancellationToken).ConfigureAwait(false);

                if (bindSession is not null)
                {
                    await TryBindSessionAsync(stream, bindSession, isForwarding: false, _logger, cancellationToken).ConfigureAwait(false);
                }

                // Use a null logger so the agent protocol packets don't end up in the log.
                var connectionLogger = NullLoggerFactory.Instance.CreateLogger<SshClient>();

                _agentConnection = new StreamSshConnection(connectionLogger, _sequencePool, stream);
                _agentConnection.SetEncryptorDecryptor(new SshAgentPacketEncryptor(), new SshAgentPacketDecryptor(_sequencePool), false, false);
            }
            catch
            {
                stream?.Dispose();
                throw;
            }
        }

        // Opens a connection to the SSH agent at 'address'.
        public static async ValueTask<Stream> OpenStreamAsync(string address, CancellationToken cancellationToken)
        {
            Stream? stream = null;
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    string normalizedPath = Path.GetFullPath(address);
                    if (!normalizedPath.StartsWith(@"\\.\pipe\", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new ArgumentException(
                            @"SSH Agent path on Windows must be a named pipe in the form of \\.\pipe\pipe-name");
                    }

                    // There is no easy way to detect if a named pipe exists or
                    // not. File.Exists is the fastest but will actually open a
                    // connection and close it. For the ssh-agent implementation
                    // that won't matter as it is configured to allow multiple
                    // connections.
                    if (!File.Exists(normalizedPath))
                    {
                        throw new FileNotFoundException(address);
                    }

                    NamedPipeClientStream pipe = new NamedPipeClientStream(
                        ".",
                        normalizedPath[9..],
                        PipeDirection.InOut,
                        PipeOptions.Asynchronous,
                        System.Security.Principal.TokenImpersonationLevel.Anonymous);
                    stream = pipe;

                    await pipe.ConnectAsync(1000, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    Socket socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                    try
                    {
                        await socket.ConnectAsync(new UnixDomainSocketEndPoint(address), cancellationToken).ConfigureAwait(false);
                        stream = new NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }

                return stream;
            }
            catch
            {
                stream?.Dispose();
                throw;
            }
        }

        /*
            Binds the agent connection to the SSH session using the 'session-bind@openssh.com' extension.

            This enables the agent to apply per-destination constraints ('ssh-add -h') and, for forwarded
            connections, to know which hosts the connection passed through.

            byte             SSH_AGENTC_EXTENSION
            string           "session-bind@openssh.com"
            string           hostkey
            string           session identifier
            string           signature
            bool             is_forwarding
        */
        public static async ValueTask<bool> TryBindSessionAsync(Stream stream, SshConnectionInfo connectionInfo, bool isForwarding, ILogger<SshClient> logger, CancellationToken ct)
        {
            byte[]? hostKey = connectionInfo.InitialServerKey;
            byte[]? sessionId = connectionInfo.SessionId;
            byte[]? signature = connectionInfo.InitialExchangeHashSignature;
            if (hostKey is null || sessionId is null || signature is null)
            {
                logger.SshAgentSessionBindFailed();
                return false;
            }

            await stream.WriteAsync(CreateBindSessionRequest(hostKey, sessionId, signature, isForwarding), ct).ConfigureAwait(false);

            byte[] buffer = new byte[4];
            await stream.ReadExactlyAsync(buffer, ct).ConfigureAwait(false);
            uint responseLength = BinaryPrimitives.ReadUInt32BigEndian(buffer);
            if (responseLength == 0 || responseLength > 256)
            {
                throw new InvalidDataException($"Unexpected SSH Agent response length ({responseLength}).");
            }
            buffer = new byte[responseLength];
            await stream.ReadExactlyAsync(buffer, ct).ConfigureAwait(false);

            // Agents that don't support the extension respond with SSH_AGENT_FAILURE.
            bool bound = (MessageId)buffer[0] == SSH_AGENT_SUCCESS;
            if (!bound)
            {
                logger.SshAgentSessionBindFailed();
            }
            return bound;

            static byte[] CreateBindSessionRequest(byte[] hostKey, byte[] sessionId, byte[] signature, bool isForwarding)
            {
                byte[] payload;
                {
                    using ArrayWriter payloadWriter = new();
                    payloadWriter.WriteMessageId(SSH_AGENTC_EXTENSION);
                    payloadWriter.WriteString(SessionBindExtension);
                    payloadWriter.WriteString(hostKey);
                    payloadWriter.WriteString(sessionId);
                    payloadWriter.WriteString(signature);
                    payloadWriter.WriteBoolean(isForwarding);
                    payload = payloadWriter.ToArray();
                }

                // The SSH Agent protocol frames messages with a 4-byte length.
                using ArrayWriter requestWriter = new();
                requestWriter.WriteString(payload);
                return requestWriter.ToArray();
            }
        }

        public async Task<byte[]?> TrySignAsync(Name algorithm, ReadOnlyMemory<byte> publicKey, byte[] data, CancellationToken ct)
        {
            var connection = GetAgentConnection();
            // SSH_AGENTC_SIGN_REQUEST
            {
                using var requestIdentitiesMsg = CreateSignRequestMessage(algorithm, _sequencePool, publicKey, data);
                await connection.SendPacketAsync(requestIdentitiesMsg.Move(), ct).ConfigureAwait(false);
            }
            {
                using var response = await connection.ReceivePacketAsync(ct, MaxPacketSize);
                return TryGetSignature(response);
            }
        }

        public void Dispose()
        {
            _agentConnection?.Dispose();
        }

        private StreamSshConnection GetAgentConnection()
        {
            return _agentConnection ?? throw new InvalidOperationException("Not connected");
        }

        public async Task<List<Identity>> RequestIdentitiesAsync(CancellationToken ct)
        {
            var connection = GetAgentConnection();
            // SSH_AGENTC_REQUEST_IDENTITIES
            {
                using var requestIdentitiesMsg = CreateRequestIdentitiesMessage(_sequencePool);
                await connection.SendPacketAsync(requestIdentitiesMsg.Move(), ct).ConfigureAwait(false);
            }
            // SSH_AGENT_IDENTITIES_ANSWER
            {
                using var response = await connection.ReceivePacketAsync(ct, MaxPacketSize);
                return GetIdentities(response);
            }
        }

        private static Packet CreateRequestIdentitiesMessage(SequencePool sequencePool)
        {
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(SSH_AGENTC_REQUEST_IDENTITIES);
            return packet.Move();
        }

        private static Packet CreateSignRequestMessage(Name algorithm, SequencePool sequencePool, ReadOnlyMemory<byte> publicKey, byte[] data)
        {
            uint flags = algorithm == AlgorithmNames.RsaSshSha2_512 ? SSH_AGENT_RSA_SHA2_512
                        : algorithm == AlgorithmNames.RsaSshSha2_256 ? SSH_AGENT_RSA_SHA2_256
                        : 0;
            /*
                byte             SSH_AGENTC_SIGN_REQUEST
                string           key blob
                string           data
                uint32           flags
            */
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(SSH_AGENTC_SIGN_REQUEST);
            writer.WriteString(publicKey);
            writer.WriteString(data);
            writer.WriteUInt32(flags);
            return packet.Move();
        }

        private static List<Identity> GetIdentities(ReadOnlyPacket packet)
        {
            /*
                    byte             SSH_AGENT_IDENTITIES_ANSWER
                    uint32           nkeys

                    string           key blob
                    string           comment
            */
            var reader = packet.GetReader();
            reader.ReadMessageId(SSH_AGENT_IDENTITIES_ANSWER);
            int nkeys = (int)reader.ReadUInt32();
            List<Identity> keys = new(capacity: nkeys);
            for (int i = 0; i < nkeys; i++)
            {
                SshKeyData key = reader.ReadSshKey();
                string comment = reader.ReadUtf8String();
                keys.Add(new Identity() { Comment = comment, PublicKey = key });
            }
            return keys;
        }

        private static byte[]? TryGetSignature(ReadOnlyPacket packet)
        {
            /*
                byte             SSH_AGENT_SIGN_RESPONSE
                string           signature
            */
            var reader = packet.GetReader();
            var id = reader.ReadMessageId();
            if (id == SSH_AGENT_SIGN_RESPONSE)
            {
                byte[] signature = reader.ReadStringAsByteArray();
                return signature;
            }
            else
            {
                Debug.Assert(id == SSH_AGENT_FAILURE);
                return null;
            }
        }

        sealed class SshAgentPacketEncryptor : IPacketEncryptor
        {
            public void Dispose()
            { }

            public void Encrypt(uint sequenceNumber, Packet packet, Sequence buffer)
            {
                // Ignore the header and encrypt the payload as expected by the SSH Agent.
                ReadOnlySequence<byte> payload = packet.Payload;
                int totalLength = (int)(4 + payload.Length);
                Span<byte> dst = buffer.AllocGetSpan(totalLength);
                BinaryPrimitives.WriteUInt32BigEndian(dst, (uint)payload.Length);
                payload.CopyTo(dst.Slice(4), (int)payload.Length);
                buffer.AppendAlloced(totalLength);
            }
        }

        sealed class SshAgentPacketDecryptor : IPacketDecryptor
        {
            private readonly SequencePool _sequencePool;
            private int _currentPacketLength = -1;

            public SshAgentPacketDecryptor(SequencePool sequencePool)
            {
                _sequencePool = sequencePool;
            }

            public void Dispose()
            { }

            public bool TryDecrypt(Sequence receiveBuffer, uint sequenceNumber, int maxLength, out Packet packet)
            {
                packet = new Packet(null);

                const int LengthSize = 4;
                int packetLength = _currentPacketLength;
                if (packetLength == -1)
                {
                    // Wait for the packet length.
                    if (receiveBuffer.Length < LengthSize)
                    {
                        return false;
                    }

                    // Decode packet length into _currentPacketLength.
                    Span<byte> lengthSpan = stackalloc byte[LengthSize];
                    receiveBuffer.CopyTo(lengthSpan, length: LengthSize);
                    _currentPacketLength = packetLength = (int)BinaryPrimitives.ReadUInt32BigEndian(lengthSpan);
                    receiveBuffer.Remove(LengthSize);
                }

                if (packetLength > MaxPacketSize)
                {
                    throw new InvalidDataException($"SSH Agent packet length ({packetLength}) exceeds maximum packet length.");
                }

                // Wait for the packet content.
                if (receiveBuffer.Length >= _currentPacketLength)
                {
                    Sequence decoded = _sequencePool.RentSequence();

                    // Translate from the SSH Agent packet format to the SSH packet format.

                    byte paddingLength = 0;
                    int dstPacketLength = packetLength + 1 + paddingLength; // add 1 byte for the padding length
                    int totalLength = 4 + dstPacketLength; // 4 bytes for the length field
                    Span<byte> dst = decoded.AllocGetSpan(4 + dstPacketLength);

                    // packet_length
                    BinaryPrimitives.WriteUInt32BigEndian(dst, (uint)dstPacketLength);
                    // padding_length
                    dst[4] = 0;
                    // payload
                    receiveBuffer.CopyTo(dst.Slice(5), packetLength);

                    decoded.AppendAlloced(totalLength);

                    receiveBuffer.Remove(packetLength);

                    _currentPacketLength = -1;  // start decoding a new packet

                    packet = new Packet(decoded, checkHeader: false);

                    return true;
                }
                return false;
            }
        }
    }
}