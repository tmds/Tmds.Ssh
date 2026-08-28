// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;

namespace Tmds.Ssh;

// Diffie-Hellman Key Exchange: https://tools.ietf.org/html/rfc4253#section-8
// The SHA-2 based algorithm names are defined by https://www.rfc-editor.org/rfc/rfc8268.
class DiffieHellmanKeyExchange : KeyExchange<DiffieHellmanKeyExchange.KeyPair, BigInteger>
{
    // The size of the private exponent.
    // RFC 4419 section 6.2 recommends using at least twice the number of bits of the
    // symmetric key material that is derived from the exchange. OpenSSH uses the same size.
    private const int PrivateKeyBitLength = 512;

    private readonly DiffieHellmanGroup? _group;

    public DiffieHellmanKeyExchange(DiffieHellmanGroup group, HashAlgorithmName hashAlgorithmName) : base(hashAlgorithmName)
    {
        _group = group;
    }

    // Used by the derived class that learns the group from the server.
    protected DiffieHellmanKeyExchange(HashAlgorithmName hashAlgorithmName) : base(hashAlgorithmName)
    { }

    protected virtual DiffieHellmanGroup Group => _group!;

    protected virtual MessageId InitMessageId => MessageId.SSH_MSG_KEXDH_INIT;

    protected override KeyPair GenerateKeyPair(KeyExchangeContext context)
        => KeyPair.Generate(Group);

    protected override Packet CreateInitMessage(SequencePool sequencePool, KeyPair keyPair)
    {
        /*
            byte      SSH_MSG_KEXDH_INIT
            mpint     e
         */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(InitMessageId);
        writer.WriteMPInt(keyPair.PublicKey);
        return packet.Move();
    }

    protected override (SshKeyData publicHostKey, BigInteger serverPublicKey, ReadOnlySequence<byte> exchangeHashSignature) ParseReplyMessage(ReadOnlyPacket packet)
    {
        /*
            byte      SSH_MSG_KEXDH_REPLY
            string    server public host key and certificates (K_S)
            mpint     f
            string    signature of H
         */
        var reader = packet.GetReader();
        reader.ReadMessageId(ReplyMessageId);
        SshKeyData public_host_key = reader.ReadSshKey();
        BigInteger f = reader.ReadMPInt();
        ReadOnlySequence<byte> exchange_hash_signature = reader.ReadStringAsBytes();
        reader.ReadEnd();
        return (public_host_key, f, exchange_hash_signature);
    }

    protected override byte[] DeriveSharedSecret(KeyPair clientKeyPair, BigInteger serverPublicKey)
    {
        DiffieHellmanGroup group = Group;

        if (!group.IsValidPublicKey(serverPublicKey))
        {
            throw new ProtocolException("The server sent an invalid Diffie-Hellman public key.");
        }

        BigInteger sharedSecret = BigInteger.ModPow(serverPublicKey, clientKeyPair.PrivateKey, group.P);
        return sharedSecret.ToMPIntByteArray();
    }

    protected override byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, ReadOnlyMemory<byte> public_host_key, KeyPair clientKeyPair, BigInteger serverPublicKey, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName)
    {
        /*
            string    V_C, the client's identification string (CR and LF excluded)
            string    V_S, the server's identification string (CR and LF excluded)
            string    I_C, the payload of the client's SSH_MSG_KEXINIT
            string    I_S, the payload of the server's SSH_MSG_KEXINIT
            string    K_S, the host key
            [ the group exchange parameters, see RFC 4419 ]
            mpint     e, exchange value sent by the client
            mpint     f, exchange value sent by the server
            mpint     K, the shared secret
         */
        using Sequence sequence = sequencePool.RentSequence();
        var writer = new SequenceWriter(sequence);
        writer.WriteString(connectionInfo.ClientIdentificationString!);
        writer.WriteString(connectionInfo.ServerIdentificationString!);
        writer.WriteString(clientKexInitMsg.Payload);
        writer.WriteString(serverKexInitMsg.Payload);
        writer.WriteString(public_host_key);
        WriteGroupExchangeParameters(ref writer);
        writer.WriteMPInt(clientKeyPair.PublicKey);
        writer.WriteMPInt(serverPublicKey);
        writer.WriteString(sharedSecret);

        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithmName);
        foreach (var segment in sequence.AsReadOnlySequence())
        {
            hash.AppendData(segment.Span);
        }
        return hash.GetHashAndReset();
    }

    // The group exchange includes the negotiated group in the exchange hash.
    protected virtual void WriteGroupExchangeParameters(ref SequenceWriter writer)
    { }

    protected override void DisposeKeyPair(KeyPair keyPair)
    { }

    internal sealed class KeyPair
    {
        private KeyPair(BigInteger privateKey, BigInteger publicKey)
        {
            PrivateKey = privateKey;
            PublicKey = publicKey;
        }

        // x
        public BigInteger PrivateKey { get; }
        // e = g^x mod p
        public BigInteger PublicKey { get; }

        public static KeyPair Generate(DiffieHellmanGroup group)
        {
            // All groups we accept are larger than the private key.
            Debug.Assert(group.PBitLength > PrivateKeyBitLength);

            Span<byte> buffer = stackalloc byte[PrivateKeyBitLength / 8];
            try
            {
                // Generating an invalid public key is not expected for the groups we accept.
                for (int attempt = 0; attempt < 10; attempt++)
                {
                    RandomBytes.Fill(buffer);
                    // Set the most significant bit so the exponent has the full size.
                    buffer[0] |= 0x80;

                    BigInteger privateKey = new BigInteger(buffer, isUnsigned: true, isBigEndian: true);
                    BigInteger publicKey = BigInteger.ModPow(group.G, privateKey, group.P);

                    if (group.IsValidPublicKey(publicKey))
                    {
                        return new KeyPair(privateKey, publicKey);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }

            throw new ProtocolException("Cannot generate a Diffie-Hellman key pair for the group.");
        }
    }
}
