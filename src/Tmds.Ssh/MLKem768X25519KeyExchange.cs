// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics;
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
sealed class MLKem768X25519KeyExchange : KeyExchange<MLKem768X25519KeyExchange.KeyPair, byte[]>
{
    internal readonly record struct KeyPair(MlKemKey MlKemKey, AsymmetricCipherKeyPair X25519KeyPair);

    public MLKem768X25519KeyExchange() : base(HashAlgorithmName.SHA256)
    { }

    internal abstract class MlKemKey : IDisposable
    {
        public abstract byte[] ExportEncapsulationKey();
        public abstract byte[] CalculateRawSecretAgreement(X25519Agreement x25519Agreement, byte[] s_reply);
        public virtual void Dispose() { }
    }

    private sealed class SystemMlKemKey : MlKemKey
    {
        private readonly MLKem _mlKem;

        public SystemMlKemKey(MLKem mlKem)
        {
            _mlKem = mlKem;
        }

        public override byte[] ExportEncapsulationKey() => _mlKem.ExportEncapsulationKey();

        public override byte[] CalculateRawSecretAgreement(X25519Agreement x25519Agreement, byte[] s_reply)
        {
            var rawSecretAgreement = new byte[MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes + x25519Agreement.AgreementSize];

            _mlKem.Decapsulate(s_reply.AsSpan(0, MLKemAlgorithm.MLKem768.CiphertextSizeInBytes), rawSecretAgreement.AsSpan(0, MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes));

            var x25519PublicKey = new X25519PublicKeyParameters(s_reply, MLKemAlgorithm.MLKem768.CiphertextSizeInBytes);
            x25519Agreement.CalculateAgreement(x25519PublicKey, rawSecretAgreement, MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes);

            return rawSecretAgreement;
        }

        public override void Dispose() => _mlKem.Dispose();
    }

    private sealed class BouncyCastleMlKemKey : MlKemKey
    {
        private readonly AsymmetricCipherKeyPair _keyPair;

        public BouncyCastleMlKemKey(AsymmetricCipherKeyPair keyPair)
        {
            _keyPair = keyPair;
        }

        public override byte[] ExportEncapsulationKey() => ((MLKemPublicKeyParameters)_keyPair.Public).GetEncoded();

        public override byte[] CalculateRawSecretAgreement(X25519Agreement x25519Agreement, byte[] s_reply)
        {
            var mlkem768Decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
            mlkem768Decapsulator.Init(_keyPair.Private);

            var rawSecretAgreement = new byte[mlkem768Decapsulator.SecretLength + x25519Agreement.AgreementSize];

            mlkem768Decapsulator.Decapsulate(s_reply, 0, mlkem768Decapsulator.EncapsulationLength, rawSecretAgreement, 0, mlkem768Decapsulator.SecretLength);

            var x25519PublicKey = new X25519PublicKeyParameters(s_reply, mlkem768Decapsulator.EncapsulationLength);
            x25519Agreement.CalculateAgreement(x25519PublicKey, rawSecretAgreement, mlkem768Decapsulator.SecretLength);

            return rawSecretAgreement;
        }
    }

    protected override KeyPair GenerateKeyPair(KeyExchangeContext context)
    {
        using (var randomGenerator = new CryptoApiRandomGenerator())
        {
            MlKemKey mlKemKey;
            if (MLKem.IsSupported)
            {
                mlKemKey = new SystemMlKemKey(MLKem.GenerateKey(MLKemAlgorithm.MLKem768));
            }
            else
            {
                var mlkem768KeyPairGenerator = new MLKemKeyPairGenerator();
                mlkem768KeyPairGenerator.Init(new MLKemKeyGenerationParameters(new SecureRandom(randomGenerator), MLKemParameters.ml_kem_768));
                mlKemKey = new BouncyCastleMlKemKey(mlkem768KeyPairGenerator.GenerateKeyPair());
            }

            var x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom(randomGenerator)));
            var x25519KeyPair = x25519KeyPairGenerator.GenerateKeyPair();

            return new KeyPair(mlKemKey, x25519KeyPair);
        }
    }

    protected override Packet CreateInitMessage(SequencePool sequencePool, KeyPair keyPair)
    {
        byte[] c_init = keyPair.MlKemKey.ExportEncapsulationKey();
        int keySize = c_init.Length;

        Array.Resize(ref c_init, keySize + X25519PublicKeyParameters.KeySize);
        ((X25519PublicKeyParameters)keyPair.X25519KeyPair.Public).Encode(c_init, keySize);

        return CreateHybridInitMessage(sequencePool, c_init);
    }

    protected override (SshKeyData publicHostKey, byte[] serverPublicKey, ReadOnlySequence<byte> exchangeHashSignature) ParseReplyMessage(ReadOnlyPacket packet)
    {
        var reply = ParseHybridReply(packet);
        return (reply.public_host_key, reply.s_reply, reply.exchange_hash_signature);
    }

    protected override byte[] DeriveSharedSecret(KeyPair clientKeyPair, byte[] serverPublicKey)
    {
        var x25519Agreement = new X25519Agreement();
        x25519Agreement.Init(clientKeyPair.X25519KeyPair.Private);

        byte[] rawSecretAgreement = clientKeyPair.MlKemKey.CalculateRawSecretAgreement(x25519Agreement, serverPublicKey);

        var sharedSecret = SHA256.HashData(rawSecretAgreement);
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
    }

    protected override byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, ReadOnlyMemory<byte> public_host_key, KeyPair clientKeyPair, byte[] serverPublicKey, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName)
    {
        byte[] c_init = clientKeyPair.MlKemKey.ExportEncapsulationKey();
        int keySize = c_init.Length;

        Array.Resize(ref c_init, keySize + X25519PublicKeyParameters.KeySize);
        ((X25519PublicKeyParameters)clientKeyPair.X25519KeyPair.Public).Encode(c_init, keySize);

        return Curve25519KeyExchange.CalculateCurve25519ExchangeHash(sequencePool, connectionInfo, clientKexInitMsg, serverKexInitMsg, public_host_key, c_init, serverPublicKey, sharedSecret, hashAlgorithmName);
    }

    protected override void DisposeKeyPair(KeyPair keyPair)
    {
        keyPair.MlKemKey.Dispose();
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
