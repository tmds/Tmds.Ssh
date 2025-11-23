// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
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

    internal readonly record struct KeyPair(AsymmetricCipherKeyPair Sntrup761KeyPair, AsymmetricCipherKeyPair X25519KeyPair);

    protected override KeyPair GenerateKeyPair(KeyExchangeContext context)
    {
        using (var randomGenerator = new CryptoApiRandomGenerator())
        {
            var sntrup761KeyPairGenerator = new SNtruPrimeKeyPairGenerator();
            sntrup761KeyPairGenerator.Init(new SNtruPrimeKeyGenerationParameters(new SecureRandom(randomGenerator), SNtruPrimeParameters.sntrup761));
            var sntrup761KeyPair = sntrup761KeyPairGenerator.GenerateKeyPair();

            var x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom(randomGenerator)));
            var x25519KeyPair = x25519KeyPairGenerator.GenerateKeyPair();

            return new KeyPair(sntrup761KeyPair, x25519KeyPair);
        }
    }

    protected override Packet CreateInitMessage(SequencePool sequencePool, KeyPair keyPair)
    {
        byte[] q_c = ((SNtruPrimePublicKeyParameters)keyPair.Sntrup761KeyPair.Public).GetEncoded();
        int sntrup761PublicKeySize = q_c.Length;
        Array.Resize(ref q_c, sntrup761PublicKeySize + X25519PublicKeyParameters.KeySize);
        Buffer.BlockCopy(((X25519PublicKeyParameters)keyPair.X25519KeyPair.Public).GetEncoded(), 0, q_c, sntrup761PublicKeySize, X25519PublicKeyParameters.KeySize);

        return Curve25519KeyExchange.CreateEcdhInitMessage(sequencePool, q_c);
    }

    protected override (SshKeyData publicHostKey, byte[] serverPublicKey, ReadOnlySequence<byte> exchangeHashSignature) ParseReplyMessage(ReadOnlyPacket packet)
    {
        var reply = Curve25519KeyExchange.ParseEcdhReply(packet);
        return (reply.public_host_key, reply.q_s, reply.exchange_hash_signature);
    }

    protected override byte[] DeriveSharedSecret(KeyPair clientKeyPair, byte[] serverPublicKey)
    {
        return DeriveSharedSecret(clientKeyPair.Sntrup761KeyPair.Private, clientKeyPair.X25519KeyPair.Private, serverPublicKey);
    }

    protected override byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, ReadOnlyMemory<byte> public_host_key, KeyPair clientKeyPair, byte[] serverPublicKey, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName)
    {
        byte[] q_c = ((SNtruPrimePublicKeyParameters)clientKeyPair.Sntrup761KeyPair.Public).GetEncoded();
        int sntrup761PublicKeySize = q_c.Length;
        Array.Resize(ref q_c, sntrup761PublicKeySize + X25519PublicKeyParameters.KeySize);
        Buffer.BlockCopy(((X25519PublicKeyParameters)clientKeyPair.X25519KeyPair.Public).GetEncoded(), 0, q_c, sntrup761PublicKeySize, X25519PublicKeyParameters.KeySize);

        return Curve25519KeyExchange.CalculateCurve25519ExchangeHash(sequencePool, connectionInfo, clientKexInitMsg, serverKexInitMsg, public_host_key, q_c, serverPublicKey, sharedSecret, hashAlgorithmName);
    }

    protected override void DisposeKeyPair(KeyPair keyPair)
    { }

    private static byte[] DeriveSharedSecret(AsymmetricKeyParameter sntrup761PrivateKey, AsymmetricKeyParameter x25519PrivateKey, byte[] q_s)
    {
        var sntrup761Extractor = new SNtruPrimeKemExtractor((SNtruPrimePrivateKeyParameters)sntrup761PrivateKey);
        byte[] rawSecretAgreement = sntrup761Extractor.ExtractSecret(q_s[..sntrup761Extractor.EncapsulationLength]);
        int sntrup761SecretLength = rawSecretAgreement.Length;

        var x25519Agreement = new X25519Agreement();
        x25519Agreement.Init(x25519PrivateKey);

        var x25519PublicKey = new X25519PublicKeyParameters(q_s, sntrup761Extractor.EncapsulationLength);
        Array.Resize(ref rawSecretAgreement, sntrup761SecretLength + x25519Agreement.AgreementSize);

        x25519Agreement.CalculateAgreement(x25519PublicKey, rawSecretAgreement, sntrup761SecretLength);

        var sharedSecret = SHA512.HashData(rawSecretAgreement);
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
    }
}
