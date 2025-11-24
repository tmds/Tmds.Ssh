// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;

namespace Tmds.Ssh;

// ECDH Key Exchange: https://tools.ietf.org/html/rfc5656#section-4
class ECDHKeyExchange : KeyExchange<ECDiffieHellman, ECPoint>
{
    private readonly ECCurve _ecCurve;

    public ECDHKeyExchange(ECCurve ecCurve, HashAlgorithmName hashAlgorithmName) : base(hashAlgorithmName)
    {
        _ecCurve = ecCurve;
    }

    protected override ECDiffieHellman GenerateKeyPair(KeyExchangeContext context)
    {
        return ECDiffieHellman.Create(_ecCurve);
    }

    protected override Packet CreateInitMessage(SequencePool sequencePool, ECDiffieHellman keyPair)
    {
        using ECDiffieHellmanPublicKey myPublicKey = keyPair.PublicKey;
        ECPoint publicKey = myPublicKey.ExportParameters().Q;
        return CreateEcdhInitMessage(sequencePool, publicKey);
    }

    protected override (SshKeyData publicHostKey, ECPoint serverPublicKey, ReadOnlySequence<byte> exchangeHashSignature) ParseReplyMessage(ReadOnlyPacket packet)
    {
        var reply = ParseEcdhReply(packet);
        return (reply.public_host_key, reply.q_s, reply.exchange_hash_signature);
    }

    protected override byte[] DeriveSharedSecret(ECDiffieHellman clientKeyPair, ECPoint serverPublicKey)
    {
        return DeriveSharedSecret(clientKeyPair, _ecCurve, serverPublicKey);
    }

    protected override byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, ReadOnlyMemory<byte> public_host_key, ECDiffieHellman clientKeyPair, ECPoint serverPublicKey, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName)
    {
        using ECDiffieHellmanPublicKey myPublicKey = clientKeyPair.PublicKey;
        ECPoint clientPublicKey = myPublicKey.ExportParameters().Q;
        return CalculateEcdhExchangeHash(sequencePool, connectionInfo, clientKexInitMsg, serverKexInitMsg, public_host_key, clientPublicKey, serverPublicKey, sharedSecret, hashAlgorithmName);
    }

    protected override void DisposeKeyPair(ECDiffieHellman keyPair)
    {
        keyPair.Dispose();
    }

    private static byte[] CalculateEcdhExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, ReadOnlyMemory<byte> public_host_key, ECPoint q_c, ECPoint q_s, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName)
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

    private static byte[] DeriveSharedSecret(ECDiffieHellman ecdh, ECCurve curve, ECPoint q)
    {
        ECParameters parameters = new ECParameters
        {
            Curve = curve,
            Q = q
        };
        using ECDiffieHellman peerEcdh = ECDiffieHellman.Create(parameters);
        using ECDiffieHellmanPublicKey peerPublicKey = peerEcdh.PublicKey;
        byte[] rawSecretAgreement = ecdh.DeriveRawSecretAgreement(peerPublicKey);
        var sharedSecret = rawSecretAgreement.ToBigInteger();
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret.ToMPIntByteArray();
    }

    private static Packet CreateEcdhInitMessage(SequencePool sequencePool, ECPoint q_c)
    {
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_KEX_ECDH_INIT);
        writer.WriteString(q_c);
        return packet.Move();
    }

    private static (
        SshKeyData public_host_key,
        ECPoint q_s,
        ReadOnlySequence<byte> exchange_hash_signature)
        ParseEcdhReply(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        reader.ReadMessageId(MessageId.SSH_MSG_KEX_ECDH_REPLY);
        SshKeyData public_host_key = reader.ReadSshKey();
        ECPoint q_s = reader.ReadStringAsECPoint();
        ReadOnlySequence<byte> exchange_hash_signature = reader.ReadStringAsBytes();
        reader.ReadEnd();
        return (
            public_host_key,
            q_s,
            exchange_hash_signature);
    }
}
