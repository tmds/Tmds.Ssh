// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using System.Formats.Asn1;

namespace Tmds.Ssh;

class RsaPublicKey : PublicKey
{
    private readonly BigInteger _e;
    private readonly BigInteger _n;

    public RsaPublicKey(BigInteger e, BigInteger n)
    {
        _e = e;
        _n = n;
    }

    public int KeySize => _n.GetByteCount(isUnsigned: true) * 8;

    public static RsaPublicKey CreateFromSshKey(byte[] key)
    {
        SequenceReader reader = new SequenceReader(key);
        reader.ReadName(AlgorithmNames.SshRsa);
        BigInteger e = reader.ReadMPInt();
        BigInteger n = reader.ReadMPInt();
        reader.ReadEnd();
        return new RsaPublicKey(e, n);
    }

    internal override bool VerifySignature(IReadOnlyList<Name> allowedAlgorithms, Span<byte> data, ReadOnlySequence<byte> signature)
    {
        var reader = new SequenceReader(signature);
        Name algorithmName = reader.ReadName(allowedAlgorithms);

        HashAlgorithmName hashAlgorithm;
        if (algorithmName == AlgorithmNames.RsaSshSha2_256)
        {
            hashAlgorithm = HashAlgorithmName.SHA256;
        }
        else if (algorithmName == AlgorithmNames.RsaSshSha2_512)
        {
            hashAlgorithm = HashAlgorithmName.SHA512;
        }
        else
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return false;
        }

        var rsaParameters = new RSAParameters
        {
            Exponent = _e.ToByteArray(isUnsigned: true, isBigEndian: true),
            Modulus = _n.ToByteArray(isUnsigned: true, isBigEndian: true)
        };
        using var rsa = RSA.Create(rsaParameters);
        int signatureLength = rsa.KeySize / 8;

        ReadOnlySequence<byte> signatureData = reader.ReadStringAsBytes(maxLength: signatureLength);
        reader.ReadEnd();

        return rsa.VerifyData(data, signatureData.ToArray(), hashAlgorithm, RSASignaturePadding.Pkcs1);
    }
}
