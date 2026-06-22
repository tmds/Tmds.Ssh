// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pqc.Crypto.NtruPrime;
using Org.BouncyCastle.Security;

namespace Tmds.Ssh;

// Key Exchange Method Using Hybrid Streamlined NTRU Prime sntrup761 and X25519
// https://www.ietf.org/archive/id/draft-ietf-sshm-ntruprime-ssh-01.html
sealed class SNtruPrime761X25519KeyExchange : KeyExchange<SNtruPrime761X25519KeyExchange.KeyPair, byte[]>
{
    public SNtruPrime761X25519KeyExchange() : base(HashAlgorithmName.SHA512)
    { }

    internal readonly record struct KeyPair(AsymmetricCipherKeyPair Sntrup761KeyPair, X25519Key X25519Key);

    protected override KeyPair GenerateKeyPair(KeyExchangeContext context)
    {
        using (var randomGenerator = new CryptoApiRandomGenerator())
        {
            var sntrup761KeyPairGenerator = new SNtruPrimeKeyPairGenerator();
            sntrup761KeyPairGenerator.Init(new SNtruPrimeKeyGenerationParameters(new SecureRandom(randomGenerator), SNtruPrimeParameters.sntrup761));
            var sntrup761KeyPair = sntrup761KeyPairGenerator.GenerateKeyPair();

            var x25519Key = X25519Key.Generate();

            return new KeyPair(sntrup761KeyPair, x25519Key);
        }
    }

    protected override Packet CreateInitMessage(SequencePool sequencePool, KeyPair keyPair)
    {
        byte[] sntrup761PublicKey = ((SNtruPrimePublicKeyParameters)keyPair.Sntrup761KeyPair.Public).GetEncoded();
        byte[] x25519PublicKey = keyPair.X25519Key.ExportPublicKey();

        byte[] q_c = new byte[sntrup761PublicKey.Length + x25519PublicKey.Length];
        sntrup761PublicKey.CopyTo(q_c.AsSpan());
        x25519PublicKey.CopyTo(q_c.AsSpan(sntrup761PublicKey.Length));

        return Curve25519KeyExchange.CreateEcdhInitMessage(sequencePool, q_c);
    }

    protected override (SshKeyData publicHostKey, byte[] serverPublicKey, ReadOnlySequence<byte> exchangeHashSignature) ParseReplyMessage(ReadOnlyPacket packet)
    {
        var reply = Curve25519KeyExchange.ParseEcdhReply(packet);
        return (reply.public_host_key, reply.q_s, reply.exchange_hash_signature);
    }

    protected override byte[] DeriveSharedSecret(KeyPair clientKeyPair, byte[] serverPublicKey)
    {
        var sntrup761Extractor = new SNtruPrimeKemExtractor((SNtruPrimePrivateKeyParameters)clientKeyPair.Sntrup761KeyPair.Private);
        byte[] sntrup761Secret = sntrup761Extractor.ExtractSecret(serverPublicKey[..sntrup761Extractor.EncapsulationLength]);

        byte[] x25519Secret = clientKeyPair.X25519Key.DeriveRawSecretAgreement(serverPublicKey.AsSpan(sntrup761Extractor.EncapsulationLength));

        var rawSecretAgreement = new byte[sntrup761Secret.Length + x25519Secret.Length];
        sntrup761Secret.CopyTo(rawSecretAgreement.AsSpan());
        x25519Secret.CopyTo(rawSecretAgreement.AsSpan(sntrup761Secret.Length));

        var sharedSecret = SHA512.HashData(rawSecretAgreement);
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
    }

    protected override byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, ReadOnlyMemory<byte> public_host_key, KeyPair clientKeyPair, byte[] serverPublicKey, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName)
    {
        byte[] sntrup761PublicKey = ((SNtruPrimePublicKeyParameters)clientKeyPair.Sntrup761KeyPair.Public).GetEncoded();
        byte[] x25519PublicKey = clientKeyPair.X25519Key.ExportPublicKey();

        byte[] q_c = new byte[sntrup761PublicKey.Length + x25519PublicKey.Length];
        sntrup761PublicKey.CopyTo(q_c.AsSpan());
        x25519PublicKey.CopyTo(q_c.AsSpan(sntrup761PublicKey.Length));

        return Curve25519KeyExchange.CalculateCurve25519ExchangeHash(sequencePool, connectionInfo, clientKexInitMsg, serverKexInitMsg, public_host_key, q_c, serverPublicKey, sharedSecret, hashAlgorithmName);
    }

    protected override void DisposeKeyPair(KeyPair keyPair)
    {
        keyPair.X25519Key.Dispose();
    }
}
