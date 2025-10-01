// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace Tmds.Ssh;

// Post-Quantum Traditional (PQ/T) Hybrid key exchange methods using ML-KEM-768 and X25519
// https://www.ietf.org/archive/id/draft-kampanakis-curdle-ssh-pq-ke-05.html
sealed class MLKem768X25519KeyExchange : Curve25519KeyExchange
{
    private readonly MLKemAlgorithm _mlKemAlgorithm = MLKemAlgorithm.MLKem768;
    private readonly MLKemParameters _mlKemParameters = MLKemParameters.ml_kem_768;
    private readonly HashAlgorithmName _hashAlgorithmName = HashAlgorithmName.SHA256;

    public override async Task<KeyExchangeOutput> TryExchangeAsync(KeyExchangeContext context, IHostKeyAuthentication hostKeyAuthentication, Packet firstPacket, KeyExchangeInput input, ILogger logger, CancellationToken ct)
    {
        var sequencePool = context.SequencePool;
        var connectionInfo = input.ConnectionInfo;

        // Send HYBRID_INIT.
        byte[] c_init = GenerateHybridPublicKey(out MLKem? mlkem, out AsymmetricCipherKeyPair? mlkem768KeyPair, out ECCurve curve, out ECDiffieHellman? ecdh, out AsymmetricCipherKeyPair? x25519KeyPair);
        await context.SendPacketAsync(CreateHybridInitMessage(sequencePool, c_init), ct).ConfigureAwait(false);

        // Receive HYBRID_REPLY.
        using Packet hybridReplyMsg = await context.ReceivePacketAsync(MessageId.SSH_MSG_KEX_HYBRID_REPLY, firstPacket.Move(), ct).ConfigureAwait(false);
        var hybridReply = ParseHybridReply(hybridReplyMsg);

        // Verify received key is valid.
        await VerifyHostKeyAsync(hostKeyAuthentication, input, hybridReply.public_host_key, ct).ConfigureAwait(false);

        // Compute shared secret.
        byte[] sharedSecret;
        try
        {
            byte[] rawSecretAgreement = DeriveHybridRawSecretAgreement(mlkem, mlkem768KeyPair, curve, ecdh, x25519KeyPair, hybridReply.s_reply);
            sharedSecret = DeriveSharedSecret(rawSecretAgreement);
        }
        catch (Exception ex)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Cannot determine shared secret.", connectionInfo, ex);
        }

        // Generate exchange hash.
        byte[] exchangeHash = CalculateExchangeHash(sequencePool, input.ConnectionInfo, input.ClientKexInitMsg, input.ServerKexInitMsg, hybridReply.public_host_key.RawData, c_init, hybridReply.s_reply, sharedSecret, _hashAlgorithmName);

        // Verify the server's signature.
        VerifySignature(connectionInfo.ServerKey, input.HostKeyAlgorithms, exchangeHash, hybridReply.exchange_hash_signature, connectionInfo);

        return CalculateKeyExchangeOutput(input, sequencePool, sharedSecret, exchangeHash, _hashAlgorithmName);
    }

    private byte[] GenerateHybridPublicKey(out MLKem? mlKem, out AsymmetricCipherKeyPair? mlkem768KeyPair, out ECCurve curve, out ECDiffieHellman? ecdh, out AsymmetricCipherKeyPair? x25519KeyPair)
    {
        mlKem = default;
        mlkem768KeyPair = default;

        byte[] publicKey;
        if (MLKem.IsSupported)
        {
            mlKem = MLKem.GenerateKey(_mlKemAlgorithm);
            publicKey = mlKem!.ExportEncapsulationKey();
        }
        else
        {
            using var randomGenerator = new CryptoApiRandomGenerator();
            var mlkem768KeyPairGenerator = new MLKemKeyPairGenerator();
            mlkem768KeyPairGenerator.Init(new MLKemKeyGenerationParameters(new SecureRandom(randomGenerator), _mlKemParameters));
            mlkem768KeyPair = mlkem768KeyPairGenerator.GenerateKeyPair();
            publicKey = ((MLKemPublicKeyParameters)mlkem768KeyPair!.Public).GetEncoded();
        }

        byte[] x25519PublicKey = GeneratePublicKey(out curve, out ecdh, out x25519KeyPair);
        Array.Resize(ref publicKey, _mlKemAlgorithm.EncapsulationKeySizeInBytes + x25519PublicKey.Length);
        Array.Copy(x25519PublicKey, 0, publicKey, _mlKemAlgorithm.EncapsulationKeySizeInBytes, x25519PublicKey.Length);

        return publicKey;
    }

    private byte[] DeriveHybridRawSecretAgreement(MLKem? mlkem, AsymmetricCipherKeyPair? mlkem768KeyPair, ECCurve curve, ECDiffieHellman? ecdh, AsymmetricCipherKeyPair? x25519KeyPair, byte[] s_reply)
    {
        var rawSecretAgreement = new byte[_mlKemAlgorithm.SharedSecretSizeInBytes];
        if (MLKem.IsSupported)
        {
            mlkem!.Decapsulate(s_reply.AsSpan(0, _mlKemAlgorithm.CiphertextSizeInBytes), rawSecretAgreement.AsSpan(0, _mlKemAlgorithm.SharedSecretSizeInBytes));
        }
        else
        {
            var mlkem768Decapsulator = new MLKemDecapsulator(_mlKemParameters);
            mlkem768Decapsulator.Init(mlkem768KeyPair!.Private);
            mlkem768Decapsulator.Decapsulate(s_reply, 0, mlkem768Decapsulator.EncapsulationLength, rawSecretAgreement, 0, mlkem768Decapsulator.SecretLength);
        }

        byte[] x25519Agreement = DeriveRawSecretAgreement(curve, ecdh, x25519KeyPair, s_reply.AsSpan(_mlKemAlgorithm.CiphertextSizeInBytes));
        Array.Resize(ref rawSecretAgreement, _mlKemAlgorithm.SharedSecretSizeInBytes + x25519Agreement.Length);
        Array.Copy(x25519Agreement, 0, rawSecretAgreement, _mlKemAlgorithm.SharedSecretSizeInBytes, x25519Agreement.Length);

        return rawSecretAgreement;
    }

    private static byte[] DeriveSharedSecret(byte[] rawSecretAgreement)
    {
        byte[] sharedSecret = SHA256.HashData(rawSecretAgreement);
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
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
