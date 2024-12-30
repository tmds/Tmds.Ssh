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
class Curve25519KeyExchange : KeyExchange
{
    private readonly HashAlgorithmName _hashAlgorithmName = HashAlgorithmName.SHA256;

    public override async Task<KeyExchangeOutput> TryExchangeAsync(KeyExchangeContext context, IHostKeyVerification hostKeyVerification, Packet firstPacket, KeyExchangeInput input, ILogger logger, CancellationToken ct)
    {
        var sequencePool = context.SequencePool;
        var connectionInfo = input.ConnectionInfo;

        AsymmetricCipherKeyPair x25519KeyPair;
        using (var randomGenerator = new CryptoApiRandomGenerator())
        {
            var x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom(randomGenerator)));
            x25519KeyPair = x25519KeyPairGenerator.GenerateKeyPair();
        }

        // Send ECDH_INIT.
        byte[] q_c = ((X25519PublicKeyParameters)x25519KeyPair.Public).GetEncoded();
        await context.SendPacketAsync(CreateEcdhInitMessage(sequencePool, q_c), ct).ConfigureAwait(false);

        // Receive ECDH_REPLY.
        using Packet ecdhReplyMsg = await context.ReceivePacketAsync(MessageId.SSH_MSG_KEX_ECDH_REPLY, firstPacket.Move(), ct).ConfigureAwait(false);
        var ecdhReply = ParceEcdhReply(ecdhReplyMsg);

        // Verify received key is valid.
        PublicKey publicHostKey = await VerifyHostKeyAsync(hostKeyVerification, input, ecdhReply.public_host_key, ct).ConfigureAwait(false);

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
        byte[] exchangeHash = CalculateExchangeHash(sequencePool, input.ConnectionInfo, input.ClientKexInitMsg, input.ServerKexInitMsg, ecdhReply.public_host_key.Data, q_c, ecdhReply.q_s, sharedSecret, _hashAlgorithmName);

        // Verify the server's signature.
        VerifySignature(publicHostKey, input.HostKeyAlgorithms, exchangeHash, ecdhReply.exchange_hash_signature, connectionInfo);

        return CalculateKeyExchangeOutput(input, sequencePool, sharedSecret, exchangeHash, _hashAlgorithmName);
    }

    private static byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, byte[] public_host_key, byte[] q_c, byte[] q_s, BigInteger sharedSecret, HashAlgorithmName hashAlgorithmName)
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

        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithmName);
        foreach (var segment in sequence.AsReadOnlySequence())
        {
            hash.AppendData(segment.Span);
        }
        return hash.GetHashAndReset();
    }

    private static BigInteger DeriveSharedSecret(AsymmetricKeyParameter privateKey, AsymmetricKeyParameter peerPublicKey)
    {
        var keyAgreement = new X25519Agreement();
        keyAgreement.Init(privateKey);

        var rawSecretAgreement = new byte[keyAgreement.AgreementSize];
        keyAgreement.CalculateAgreement(peerPublicKey, rawSecretAgreement);
        var sharedSecret = rawSecretAgreement.ToBigInteger();
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
    }

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
