// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;

namespace Tmds.Ssh;

// Curve25519 Key Exchange: https://datatracker.ietf.org/doc/html/rfc8731
class Curve25519KeyExchange : KeyExchange<AsymmetricCipherKeyPair, byte[]>
{
    public Curve25519KeyExchange() : base(HashAlgorithmName.SHA256)
    { }

    protected override AsymmetricCipherKeyPair GenerateKeyPair(KeyExchangeContext context)
    {
        using (var randomGenerator = new CryptoApiRandomGenerator())
        {
            var x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom(randomGenerator)));
            return x25519KeyPairGenerator.GenerateKeyPair();
        }
    }

    protected override Packet CreateInitMessage(SequencePool sequencePool, AsymmetricCipherKeyPair keyPair)
    {
        byte[] publicKey = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
        return CreateEcdhInitMessage(sequencePool, publicKey);
    }

    protected override (SshKeyData publicHostKey, byte[] serverPublicKey, ReadOnlySequence<byte> exchangeHashSignature) ParseReplyMessage(ReadOnlyPacket packet)
    {
        var reply = ParseEcdhReply(packet);
        return (reply.public_host_key, reply.q_s, reply.exchange_hash_signature);
    }

    protected override byte[] DeriveSharedSecret(AsymmetricCipherKeyPair clientKeyPair, byte[] serverPublicKey)
    {
        return DeriveSharedSecret(clientKeyPair.Private, new X25519PublicKeyParameters(serverPublicKey));
    }

    protected override byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, ReadOnlyMemory<byte> public_host_key, AsymmetricCipherKeyPair clientKeyPair, byte[] serverPublicKey, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName)
    {
        byte[] clientPublicKey = ((X25519PublicKeyParameters)clientKeyPair.Public).GetEncoded();
        return CalculateCurve25519ExchangeHash(sequencePool, connectionInfo, clientKexInitMsg, serverKexInitMsg, public_host_key, clientPublicKey, serverPublicKey, sharedSecret, hashAlgorithmName);
    }

    protected override void DisposeKeyPair(AsymmetricCipherKeyPair keyPair)
    { }

    internal static byte[] CalculateCurve25519ExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, ReadOnlyMemory<byte> public_host_key, byte[] q_c, byte[] q_s, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName)
    {
        /*
            string   V_C, client's identification string (CR and LF excluded)
            string   V_S, server's identification string (CR and LF excluded)
            string   I_C, payload of the client's SSH_MSG_KEXINIT
            string   I_S, payload of the server's SSH_MSG_KEXINIT
            string   K_S, server's public host key
            string   Q_C, client's ephemeral public key octet string
            string   Q_S, server's ephemeral public key octet string
            mpint    K,   shared secret
         */
        using Sequence sequence = sequencePool.RentSequence();
        var writer = new SequenceWriter(sequence);
        writer.WriteString(connectionInfo.ClientIdentificationString!);
        writer.WriteString(connectionInfo.ServerIdentificationString!);
        writer.WriteString(clientKexInitMsg.Payload);
        writer.WriteString(serverKexInitMsg.Payload);
        writer.WriteString(public_host_key);
        writer.WriteString(q_c);
        writer.WriteString(q_s);
        writer.WriteString(sharedSecret);

        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithmName);
        foreach (var segment in sequence.AsReadOnlySequence())
        {
            hash.AppendData(segment.Span);
        }
        return hash.GetHashAndReset();
    }

    private static byte[] DeriveSharedSecret(AsymmetricKeyParameter privateKey, AsymmetricKeyParameter peerPublicKey)
    {
        var keyAgreement = new X25519Agreement();
        keyAgreement.Init(privateKey);

        var rawSecretAgreement = new byte[keyAgreement.AgreementSize];
        keyAgreement.CalculateAgreement(peerPublicKey, rawSecretAgreement);
        var sharedSecret = rawSecretAgreement.ToBigInteger();
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret.ToMPIntByteArray();
    }

    internal static Packet CreateEcdhInitMessage(SequencePool sequencePool, ReadOnlySpan<byte> q_c)
    {
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_KEX_ECDH_INIT);
        writer.WriteString(q_c);
        return packet.Move();
    }

    internal static (
        SshKeyData public_host_key,
        byte[] q_s,
        ReadOnlySequence<byte> exchange_hash_signature)
        ParseEcdhReply(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        reader.ReadMessageId(MessageId.SSH_MSG_KEX_ECDH_REPLY);
        SshKeyData public_host_key = reader.ReadSshKey();
        byte[] q_s = reader.ReadStringAsByteArray();
        ReadOnlySequence<byte> exchange_hash_signature = reader.ReadStringAsBytes();
        reader.ReadEnd();
        return (
            public_host_key,
            q_s,
            exchange_hash_signature);
    }
}
