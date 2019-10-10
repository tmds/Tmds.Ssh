// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;

namespace Tmds.Ssh
{
    class RsaPublicKey : PublicKey
    {
        private readonly byte[] _e;
        private readonly byte[] _n;

        public RsaPublicKey(BigInteger e, BigInteger n) :
            base(AlgorithmNames.SshRsa)
        {
            _e = e.ToByteArray(isUnsigned: true, isBigEndian: true);
            _n = n.ToByteArray(isUnsigned: true, isBigEndian: true);
        }

        internal override bool VerifySignature(Span<byte> data, ReadOnlySequence<byte> signature)
        {
            var reader = new SequenceReader(signature);
            reader.ReadName(Format);
            ReadOnlySequence<byte> signatureData = reader.ReadStringAsBytes();
            reader.ReadEnd();

            // TODO signatureData.Length check + stackalloc
            using var rsa = RSA.Create(new RSAParameters { Exponent = _e, Modulus = _n });
            return rsa.VerifyData(data, signatureData.ToArray(), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }
    }
}