// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Tmds.Ssh;

abstract class MlDsaKey : IDisposable
{
    internal const int MlDsa44PublicKeySize = 1312;
    internal const int MlDsa44SignatureSize = 2420;
    internal const int MlDsa44SeedSize = 32;

    public abstract byte[] SignData(byte[] data, byte[] context);
    public abstract bool VerifyData(byte[] data, ReadOnlySpan<byte> signature, byte[] context);
    public virtual void Dispose() { }

    public static MlDsaKey ImportPublicKey(byte[] publicKey)
    {
        if (MLDsa.IsSupported)
        {
            return new SystemMlDsaKey(MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa44, publicKey));
        }
        return new BouncyCastleMlDsaKey(MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_44, publicKey));
    }

    public static MlDsaKey ImportPrivateSeed(byte[] seed)
    {
        if (MLDsa.IsSupported)
        {
            return new SystemMlDsaKey(MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa44, seed));
        }
        return new BouncyCastleMlDsaKey(MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_44, seed));
    }

    private sealed class SystemMlDsaKey : MlDsaKey
    {
        private readonly MLDsa _mlDsa;

        public SystemMlDsaKey(MLDsa mlDsa)
        {
            _mlDsa = mlDsa;
        }

        public override byte[] SignData(byte[] data, byte[] context)
            => _mlDsa.SignData(data, context);

        public override bool VerifyData(byte[] data, ReadOnlySpan<byte> signature, byte[] context)
            => _mlDsa.VerifyData(data, signature, context);

        public override void Dispose() => _mlDsa.Dispose();
    }

    private sealed class BouncyCastleMlDsaKey : MlDsaKey
    {
        private readonly MLDsaKeyParameters _keyParameters;

        public BouncyCastleMlDsaKey(MLDsaKeyParameters keyParameters)
        {
            _keyParameters = keyParameters;
        }

        public override byte[] SignData(byte[] data, byte[] context)
        {
            var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_44, false);
            signer.Init(true, new ParametersWithContext(_keyParameters, context));
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        public override bool VerifyData(byte[] data, ReadOnlySpan<byte> signature, byte[] context)
        {
            var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_44, false);
            signer.Init(false, new ParametersWithContext(_keyParameters, context));
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature.ToArray());
        }
    }
}
