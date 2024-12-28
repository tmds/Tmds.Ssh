// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;
using System.Numerics;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;

namespace Tmds.Ssh;

// Curve25519 Key Exchange: https://datatracker.ietf.org/doc/html/rfc8731
class Curve25519KeyExchange : IKeyExchangeAlgorithm
{
    private readonly HashAlgorithmName _hashAlgorithmName;

    public Curve25519KeyExchange(HashAlgorithmName hashAlgorithmName)
    {
        _hashAlgorithmName = hashAlgorithmName;
    }

    public async Task<KeyExchangeOutput> TryExchangeAsync(KeyExchangeContext context, IHostKeyVerification hostKeyVerification, Packet firstPacket, KeyExchangeInput input, ILogger logger, CancellationToken ct)
    {
        var sequencePool = context.SequencePool;
        var connectionInfo = input.ConnectionInfo;

        AsymmetricCipherKeyPair x25519KeyPair;
        using (var _randomGenerator = new CryptoApiRandomGenerator())
        {
            var x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom(_randomGenerator)));
            x25519KeyPair = x25519KeyPairGenerator.GenerateKeyPair();
        }

        // Send ECDH_INIT.
        var q_c = ((X25519PublicKeyParameters)x25519KeyPair.Public).GetEncoded();
        await context.SendPacketAsync(CreateEcdhInitMessage(sequencePool, q_c), ct).ConfigureAwait(false);

        // Receive ECDH_REPLY.
        using Packet ecdhReplyMsg = await context.ReceivePacketAsync(MessageId.SSH_MSG_KEX_ECDH_REPLY, firstPacket.Move(), ct).ConfigureAwait(false);
        var ecdhReply = ParceEcdhReply(ecdhReplyMsg);

        // Verify received key is valid.
        connectionInfo.ServerKey = new HostKey(ecdhReply.public_host_key);
        await hostKeyVerification.VerifyAsync(connectionInfo, ct).ConfigureAwait(false);

        var publicHostKey = PublicKey.CreateFromSshKey(ecdhReply.public_host_key);
        if (publicHostKey is RsaPublicKey rsaPublicKey && rsaPublicKey.KeySize < input.MinimumRSAKeySize)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"Server RSA key size {rsaPublicKey.KeySize} is less than {input.MinimumRSAKeySize}.", connectionInfo);
        }

        // Compute shared secret.
        BigInteger sharedSecret;
        try
        {
            sharedSecret = DeriveSharedSecret(x25519KeyPair.Private, new X25519PublicKeyParameters(ecdhReply.q_s));
        }
        catch (Exception ex)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Cannot determine shared secret.", connectionInfo, ex);
        }

        // Generate exchange hash.
        byte[] exchangeHash = CalculateExchangeHash(sequencePool, input.ConnectionInfo, input.ClientKexInitMsg, input.ServerKexInitMsg, ecdhReply.public_host_key.Data, q_c, ecdhReply.q_s, sharedSecret);

        // Verify the server's signature.
        if (!publicHostKey.VerifySignature(input.HostKeyAlgorithms, exchangeHash, ecdhReply.exchange_hash_signature))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Signature does not match host key.", connectionInfo);
        }

        byte[] sessionId = input.ConnectionInfo.SessionId ?? exchangeHash;
        byte[] initialIVC2S = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'A', sessionId, input.InitialIVC2SLength);
        byte[] initialIVS2C = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'B', sessionId, input.InitialIVS2CLength);
        byte[] encryptionKeyC2S = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'C', sessionId, input.EncryptionKeyC2SLength);
        byte[] encryptionKeyS2C = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'D', sessionId, input.EncryptionKeyS2CLength);
        byte[] integrityKeyC2S = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'E', sessionId, input.IntegrityKeyC2SLength);
        byte[] integrityKeyS2C = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'F', sessionId, input.IntegrityKeyS2CLength);

        return new KeyExchangeOutput(exchangeHash,
            initialIVS2C, encryptionKeyS2C, integrityKeyS2C,
            initialIVC2S, encryptionKeyC2S, integrityKeyC2S);
    }

    private byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, byte[] public_host_key, byte[] q_c, byte[] q_s, BigInteger sharedSecret)
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
        writer.WriteMPInt(sharedSecret);

        using IncrementalHash hash = IncrementalHash.CreateHash(_hashAlgorithmName);
        foreach (var segment in sequence.AsReadOnlySequence())
        {
            hash.AppendData(segment.Span);
        }
        return hash.GetHashAndReset();
    }

    private byte[] CalculateKey(SequencePool sequencePool, BigInteger sharedSecret, byte[] exchangeHash, byte c, byte[] sessionId, int keyLength)
    {
        // https://tools.ietf.org/html/rfc4253#section-7.2

        byte[] key = new byte[keyLength];
        int keyOffset = 0;

        // HASH(K || H || c || session_id)
        using Sequence sequence = sequencePool.RentSequence();
        var writer = new SequenceWriter(sequence);
        writer.WriteMPInt(sharedSecret);
        writer.Write(exchangeHash);
        writer.WriteByte(c);
        writer.Write(sessionId);

        using IncrementalHash hash = IncrementalHash.CreateHash(_hashAlgorithmName);
        foreach (var segment in sequence.AsReadOnlySequence())
        {
            hash.AppendData(segment.Span);
        }
        byte[] K1 = hash.GetHashAndReset();
        Append(key, K1, ref keyOffset);

        while (keyOffset != key.Length)
        {
            sequence.Clear();

            // K3 = HASH(K || H || K1 || K2)
            writer = new SequenceWriter(sequence);
            writer.WriteMPInt(sharedSecret);
            writer.Write(exchangeHash);
            writer.Write(key.AsSpan(0, keyOffset));

            foreach (var segment in sequence.AsReadOnlySequence())
            {
                hash.AppendData(segment.Span);
            }
            byte[] Kn = hash.GetHashAndReset();

            Append(key, Kn, ref keyOffset);
        }

        return key;

        static void Append(byte[] key, byte[] append, ref int offset)
        {
            int available = Math.Min(append.Length, key.Length - offset);
            append.AsSpan().Slice(0, available).CopyTo(key.AsSpan(offset));
            offset += available;
        }
    }

    private BigInteger DeriveSharedSecret(AsymmetricKeyParameter privateKey, AsymmetricKeyParameter peerPublicKey)
    {
        var keyAgreement = new X25519Agreement();
        keyAgreement.Init(privateKey);

        var rawSecretAgreement = new byte[keyAgreement.AgreementSize];
        keyAgreement.CalculateAgreement(peerPublicKey, rawSecretAgreement);
        var sharedSecret = rawSecretAgreement.ToBigInteger();
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
    }

    public void Dispose()
    { }

    private static Packet CreateEcdhInitMessage(SequencePool sequencePool, ReadOnlySpan<byte> q_c)
    {
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_KEX_ECDH_INIT);
        writer.WriteString(q_c);
        return packet.Move();
    }

    private static (
        SshKey public_host_key,
        byte[] q_s,
        ReadOnlySequence<byte> exchange_hash_signature)
        ParceEcdhReply(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        reader.ReadMessageId(MessageId.SSH_MSG_KEX_ECDH_REPLY);
        SshKey public_host_key = reader.ReadSshKey();
        byte[] q_s = reader.ReadStringAsByteArray();
        ReadOnlySequence<byte> exchange_hash_signature = reader.ReadStringAsBytes();
        reader.ReadEnd();
        return (
            public_host_key,
            q_s,
            exchange_hash_signature);
    }
}
