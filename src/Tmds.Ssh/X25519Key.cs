// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace Tmds.Ssh;

// X25519 key pair for Diffie-Hellman key exchange (RFC 7748).
abstract class X25519Key : IDisposable
{
    public abstract byte[] ExportPublicKey();
    public abstract byte[] DeriveRawSecretAgreement(ReadOnlySpan<byte> peerPublicKey);
    public virtual void Dispose() { }

    public static X25519Key Generate()
    {
#if NET11_0_OR_GREATER
        if (X25519DiffieHellman.IsSupported)
        {
            return new SystemX25519Key(X25519DiffieHellman.GenerateKey());
        }
#endif

        using (var randomGenerator = new CryptoApiRandomGenerator())
        {
            var keyPairGenerator = new X25519KeyPairGenerator();
            keyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom(randomGenerator)));
            return new BouncyCastleX25519Key(keyPairGenerator.GenerateKeyPair());
        }
    }

#if NET11_0_OR_GREATER
    private sealed class SystemX25519Key : X25519Key
    {
        private readonly X25519DiffieHellman _key;

        public SystemX25519Key(X25519DiffieHellman key)
        {
            _key = key;
        }

        public override byte[] ExportPublicKey() => _key.ExportPublicKey();

        public override byte[] DeriveRawSecretAgreement(ReadOnlySpan<byte> peerPublicKey)
        {
            using var peer = X25519DiffieHellman.ImportPublicKey(peerPublicKey);
            return _key.DeriveRawSecretAgreement(peer);
        }

        public override void Dispose() => _key.Dispose();
    }
#endif

    private sealed class BouncyCastleX25519Key : X25519Key
    {
        private readonly AsymmetricCipherKeyPair _keyPair;

        public BouncyCastleX25519Key(AsymmetricCipherKeyPair keyPair)
        {
            _keyPair = keyPair;
        }

        public override byte[] ExportPublicKey() => ((X25519PublicKeyParameters)_keyPair.Public).GetEncoded();

        public override byte[] DeriveRawSecretAgreement(ReadOnlySpan<byte> peerPublicKey)
        {
            var keyAgreement = new X25519Agreement();
            keyAgreement.Init(_keyPair.Private);
            var secret = new byte[keyAgreement.AgreementSize];
            keyAgreement.CalculateAgreement(new X25519PublicKeyParameters(peerPublicKey.ToArray()), secret);
            return secret;
        }
    }
}
