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
    private readonly byte[] _e;
    private readonly byte[] _n;

    public RsaPublicKey(byte[] e, byte[] n)
    {
        _e = e;
        _n = n;
    }

    public static RsaPublicKey CreateFromSshKey(byte[] key)
    {
        SequenceReader reader = new SequenceReader(key);
        reader.ReadName(AlgorithmNames.SshRsa);
        byte[] e = reader.ReadMPIntAsByteArray(isUnsigned: true);
        byte[] n = reader.ReadMPIntAsByteArray(isUnsigned: true);
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
            Exponent = _e,
            Modulus = _n
        };
        using var rsa = RSA.Create(rsaParameters);
        int signatureLength = rsa.KeySize / 8;

        ReadOnlySequence<byte> signatureData = reader.ReadStringAsBytes(maxLength: signatureLength);
        reader.ReadEnd();

        return rsa.VerifyData(data, signatureData.ToArray(), hashAlgorithm, RSASignaturePadding.Pkcs1);
    }
}
