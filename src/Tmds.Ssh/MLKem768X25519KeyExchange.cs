// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;

namespace Tmds.Ssh;

// Post-Quantum Traditional (PQ/T) Hybrid key exchange methods using ML-KEM-768 and X25519
// https://www.ietf.org/archive/id/draft-kampanakis-curdle-ssh-pq-ke-05.html
sealed class MLKem768X25519KeyExchange : KeyExchange<MLKem768X25519KeyExchange.KeyPair, byte[]>
{
    internal readonly record struct KeyPair(MlKemKey MlKemKey, X25519Key X25519Key);

    public MLKem768X25519KeyExchange() : base(HashAlgorithmName.SHA256)
    { }

    protected override KeyPair GenerateKeyPair(KeyExchangeContext context)
    {
        return new KeyPair(MlKemKey.Generate(), X25519Key.Generate());
    }

    protected override Packet CreateInitMessage(SequencePool sequencePool, KeyPair keyPair)
    {
        byte[] encapsulationKey = keyPair.MlKemKey.ExportEncapsulationKey();
        byte[] x25519PublicKey = keyPair.X25519Key.ExportPublicKey();

        byte[] c_init = new byte[encapsulationKey.Length + x25519PublicKey.Length];
        encapsulationKey.CopyTo(c_init.AsSpan());
        x25519PublicKey.CopyTo(c_init.AsSpan(encapsulationKey.Length));

        return CreateHybridInitMessage(sequencePool, c_init);
    }

    protected override (SshKeyData publicHostKey, byte[] serverPublicKey, ReadOnlySequence<byte> exchangeHashSignature) ParseReplyMessage(ReadOnlyPacket packet)
    {
        var reply = ParseHybridReply(packet);
        return (reply.public_host_key, reply.s_reply, reply.exchange_hash_signature);
    }

    protected override byte[] DeriveSharedSecret(KeyPair clientKeyPair, byte[] serverPublicKey)
    {
        byte[] rawSecretAgreement = clientKeyPair.MlKemKey.CalculateRawSecretAgreement(clientKeyPair.X25519Key, serverPublicKey);

        var sharedSecret = SHA256.HashData(rawSecretAgreement);
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
    }

    protected override byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, ReadOnlyMemory<byte> public_host_key, KeyPair clientKeyPair, byte[] serverPublicKey, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName)
    {
        byte[] encapsulationKey = clientKeyPair.MlKemKey.ExportEncapsulationKey();
        byte[] x25519PublicKey = clientKeyPair.X25519Key.ExportPublicKey();

        byte[] c_init = new byte[encapsulationKey.Length + x25519PublicKey.Length];
        encapsulationKey.CopyTo(c_init.AsSpan());
        x25519PublicKey.CopyTo(c_init.AsSpan(encapsulationKey.Length));

        return Curve25519KeyExchange.CalculateCurve25519ExchangeHash(sequencePool, connectionInfo, clientKexInitMsg, serverKexInitMsg, public_host_key, c_init, serverPublicKey, sharedSecret, hashAlgorithmName);
    }

    protected override void DisposeKeyPair(KeyPair keyPair)
    {
        keyPair.MlKemKey.Dispose();
        keyPair.X25519Key.Dispose();
    }

    private static Packet CreateHybridInitMessage(SequencePool sequencePool, ReadOnlySpan<byte> c_init)
    {
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_KEX_HYBRID_INIT);
        writer.WriteString(c_init);
        return packet.Move();
    }

    private static (
        SshKeyData public_host_key,
        byte[] s_reply,
        ReadOnlySequence<byte> exchange_hash_signature)
        ParseHybridReply(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        reader.ReadMessageId(MessageId.SSH_MSG_KEX_ECDH_REPLY);
        SshKeyData public_host_key = reader.ReadSshKey();
        byte[] s_reply = reader.ReadStringAsByteArray();
        ReadOnlySequence<byte> exchange_hash_signature = reader.ReadStringAsBytes();
        reader.ReadEnd();
        return (
            public_host_key,
            s_reply,
            exchange_hash_signature);
    }
}
