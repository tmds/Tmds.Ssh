// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace Tmds.Ssh;

// ML-KEM-768 key pair for hybrid post-quantum key exchange.
abstract class MlKemKey : IDisposable
{
    public abstract byte[] ExportEncapsulationKey();
    public abstract byte[] CalculateRawSecretAgreement(X25519Key x25519Key, byte[] s_reply);
    public virtual void Dispose() { }

    public static MlKemKey Generate()
    {
        if (MLKem.IsSupported)
        {
            return new SystemMlKemKey(MLKem.GenerateKey(MLKemAlgorithm.MLKem768));
        }

        using var randomGenerator = new CryptoApiRandomGenerator();
        var keyPairGenerator = new MLKemKeyPairGenerator();
        keyPairGenerator.Init(new MLKemKeyGenerationParameters(new SecureRandom(randomGenerator), MLKemParameters.ml_kem_768));
        return new BouncyCastleMlKemKey(keyPairGenerator.GenerateKeyPair());
    }

    private sealed class SystemMlKemKey : MlKemKey
    {
        private readonly MLKem _mlKem;

        public SystemMlKemKey(MLKem mlKem)
        {
            _mlKem = mlKem;
        }

        public override byte[] ExportEncapsulationKey() => _mlKem.ExportEncapsulationKey();

        public override byte[] CalculateRawSecretAgreement(X25519Key x25519Key, byte[] s_reply)
        {
            int mlKemSecretSize = MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes;
            int mlKemCiphertextSize = MLKemAlgorithm.MLKem768.CiphertextSizeInBytes;

            byte[] x25519Secret = x25519Key.DeriveRawSecretAgreement(s_reply.AsSpan(mlKemCiphertextSize));

            var rawSecretAgreement = new byte[mlKemSecretSize + x25519Secret.Length];
            _mlKem.Decapsulate(s_reply.AsSpan(0, mlKemCiphertextSize), rawSecretAgreement.AsSpan(0, mlKemSecretSize));
            x25519Secret.CopyTo(rawSecretAgreement.AsSpan(mlKemSecretSize));
            x25519Secret.AsSpan().Clear();

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

        public override byte[] CalculateRawSecretAgreement(X25519Key x25519Key, byte[] s_reply)
        {
            var mlkem768Decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
            mlkem768Decapsulator.Init(_keyPair.Private);

            byte[] x25519Secret = x25519Key.DeriveRawSecretAgreement(s_reply.AsSpan(mlkem768Decapsulator.EncapsulationLength));

            var rawSecretAgreement = new byte[mlkem768Decapsulator.SecretLength + x25519Secret.Length];
            mlkem768Decapsulator.Decapsulate(s_reply, 0, mlkem768Decapsulator.EncapsulationLength, rawSecretAgreement, 0, mlkem768Decapsulator.SecretLength);
            x25519Secret.CopyTo(rawSecretAgreement.AsSpan(mlkem768Decapsulator.SecretLength));
            x25519Secret.AsSpan().Clear();

            return rawSecretAgreement;
        }
    }
}
