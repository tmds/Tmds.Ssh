using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
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
        private const MessageId SSH_AGENT_FAILURE = (MessageId)5;
        private const MessageId SSH_AGENT_IDENTITIES_ANSWER = (MessageId)12;
        private const MessageId SSH_AGENT_SIGN_RESPONSE = (MessageId)14;
        private const uint SSH_AGENT_RSA_SHA2_256 = 2;
        private const uint SSH_AGENT_RSA_SHA2_512 = 4;

        private static EndPoint? _defaultEndPoint;

        public struct Identity
        {
            public string Comment { init; get; }
            public byte[] PublicKey { init; get; }
        }

        public static EndPoint? DefaultEndPoint
        {
            get
            {
                string? sshAuthSock = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");

                if (OperatingSystem.IsWindows())
                {
                    return null;
                }

                if (string.IsNullOrEmpty(sshAuthSock))
                {
                    return null;
                }

                _defaultEndPoint ??= new UnixDomainSocketEndPoint(sshAuthSock);

                return _defaultEndPoint;
            }
        }

        private readonly EndPoint _endPoint;
        private readonly SequencePool _sequencePool;

        private SocketSshConnection? _agentConnection;

        public SshAgent(EndPoint endPoint, SequencePool sequencePool)
        {
            _endPoint = endPoint;
            _sequencePool = sequencePool;
        }

        public async ValueTask<bool> TryConnect(CancellationToken cancellationToken)
        {
            Socket? socket = null;
            try
            {
                socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                await socket.ConnectAsync(_endPoint, cancellationToken).ConfigureAwait(false);
                _agentConnection = new SocketSshConnection(NullLoggerFactory.Instance.CreateLogger<SshClient>(), _sequencePool, socket);
                _agentConnection.SetEncryptorDecryptor(new SshAgentPacketEncryptor(), new SshAgentPacketDecryptor(_sequencePool), false, false);
                return true;
            }
            catch
            {
                socket?.Dispose();
                return false;
            }
        }

        public async Task<byte[]?> TrySignAsync(Name algorithm, byte[] publicKey, byte[] data, CancellationToken ct)
        {
            var connection = GetAgentConnection();
            // SSH_AGENTC_SIGN_REQUEST
            {
                using var requestIdentitiesMsg = CreateSignRequestMessage(algorithm, _sequencePool, publicKey, data);
                await connection.SendPacketAsync(requestIdentitiesMsg.Move(), ct).ConfigureAwait(false);
            }
            {
                using var response = await connection.ReceivePacketAsync(ct, maxLength: 30000);
                return TryGetSignature(response);
            }
        }

        public void Dispose()
        {
            _agentConnection?.Dispose();
        }

        private SocketSshConnection GetAgentConnection()
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
                using var response = await connection.ReceivePacketAsync(ct, maxLength: 30000);
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

        private static Packet CreateSignRequestMessage(Name algorithm, SequencePool sequencePool, byte[] publicKey, byte[] data)
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
                byte[] key_blob = reader.ReadStringAsBytes().ToArray();
                string comment = reader.ReadUtf8String();
                keys.Add(new Identity() { Comment = comment, PublicKey = key_blob });
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
                byte[] signature = reader.ReadStringAsBytes().ToArray();
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

                if (packetLength > maxLength)
                {
                    ThrowHelper.ThrowProtocolPacketTooLong();
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