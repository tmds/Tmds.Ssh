// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
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
#pragma warning disable SYSLIB5006 // Type is for evaluation purposes only and is subject to change or removal in future updates. Suppress this diagnostic to proceed.
    private readonly MLKemAlgorithm _mlKemAlgorithm = MLKemAlgorithm.MLKem768;
    private readonly MLKemParameters _mlKemParameters = MLKemParameters.ml_kem_768;
    private readonly HashAlgorithmName _hashAlgorithmName = HashAlgorithmName.SHA256;

    public override async Task<KeyExchangeOutput> TryExchangeAsync(KeyExchangeContext context, IHostKeyAuthentication hostKeyAuthentication, Packet firstPacket, KeyExchangeInput input, ILogger logger, CancellationToken ct)
    {
        var sequencePool = context.SequencePool;
        var connectionInfo = input.ConnectionInfo;

        MLKem? mlKem = null;
        AsymmetricCipherKeyPair? mlkem768KeyPair = null;
        AsymmetricCipherKeyPair x25519KeyPair;
        using (var randomGenerator = new CryptoApiRandomGenerator())
        {
            if (MLKem.IsSupported)
            {
                mlKem = MLKem.GenerateKey(_mlKemAlgorithm);
            }
            else
            {
                var mlkem768KeyPairGenerator = new MLKemKeyPairGenerator();
                mlkem768KeyPairGenerator.Init(new MLKemKeyGenerationParameters(new SecureRandom(randomGenerator), _mlKemParameters));
                mlkem768KeyPair = mlkem768KeyPairGenerator.GenerateKeyPair();
            }

            var x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom(randomGenerator)));
            x25519KeyPair = x25519KeyPairGenerator.GenerateKeyPair();
        }

        // Send HYBRID_INIT.
        byte[] c_init;
        if (MLKem.IsSupported)
        {
            c_init = mlKem!.ExportEncapsulationKey();
        }
        else
        {
            c_init = ((MLKemPublicKeyParameters)mlkem768KeyPair!.Public).GetEncoded();
        }

        Array.Resize(ref c_init, _mlKemAlgorithm.EncapsulationKeySizeInBytes + X25519PublicKeyParameters.KeySize);
        ((X25519PublicKeyParameters)x25519KeyPair.Public).Encode(c_init, _mlKemAlgorithm.EncapsulationKeySizeInBytes);

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
            if (MLKem.IsSupported)
            {
                sharedSecret = DeriveSharedSecret(mlKem!, x25519KeyPair.Private, hybridReply.s_reply);
            }
            else
            {
                sharedSecret = DeriveSharedSecret(mlkem768KeyPair!.Private, x25519KeyPair.Private, hybridReply.s_reply);
            }
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

    private byte[] DeriveSharedSecret(MLKem mlkem, AsymmetricKeyParameter x25519PrivateKey, byte[] s_reply)
    {
        var x25519Agreement = new X25519Agreement();
        x25519Agreement.Init(x25519PrivateKey);

        var rawSecretAgreement = new byte[_mlKemAlgorithm.SharedSecretSizeInBytes + x25519Agreement.AgreementSize];

        mlkem.Decapsulate(s_reply.AsSpan(0, _mlKemAlgorithm.CiphertextSizeInBytes), rawSecretAgreement.AsSpan(0, _mlKemAlgorithm.SharedSecretSizeInBytes));

        var x25519PublicKey = new X25519PublicKeyParameters(s_reply, _mlKemAlgorithm.CiphertextSizeInBytes);
        x25519Agreement.CalculateAgreement(x25519PublicKey, rawSecretAgreement, _mlKemAlgorithm.SharedSecretSizeInBytes);

        var sharedSecret = SHA256.HashData(rawSecretAgreement);
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
    }

    private byte[] DeriveSharedSecret(AsymmetricKeyParameter mlkem768PrivateKey, AsymmetricKeyParameter x25519PrivateKey, byte[] s_reply)
    {
        var mlkem768Decapsulator = new MLKemDecapsulator(_mlKemParameters);
        mlkem768Decapsulator.Init(mlkem768PrivateKey);

        var x25519Agreement = new X25519Agreement();
        x25519Agreement.Init(x25519PrivateKey);

        var rawSecretAgreement = new byte[mlkem768Decapsulator.SecretLength + x25519Agreement.AgreementSize];

        mlkem768Decapsulator.Decapsulate(s_reply, 0, mlkem768Decapsulator.EncapsulationLength, rawSecretAgreement, 0, mlkem768Decapsulator.SecretLength);

        var x25519PublicKey = new X25519PublicKeyParameters(s_reply, mlkem768Decapsulator.EncapsulationLength);
        x25519Agreement.CalculateAgreement(x25519PublicKey, rawSecretAgreement, mlkem768Decapsulator.SecretLength);

        var sharedSecret = SHA256.HashData(rawSecretAgreement);
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
    }
#pragma warning restore SYSLIB5006 // Type is for evaluation purposes only and is subject to change or removal in future updates. Suppress this diagnostic to proceed.

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
