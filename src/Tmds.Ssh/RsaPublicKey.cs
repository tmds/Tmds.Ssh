// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;

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

    public int KeySize => _n.Length * 8;

    public static SshKey DeterminePublicSshKey(byte[] e, byte[] n)
    {
        using var writer = new ArrayWriter();
        writer.WriteString(AlgorithmNames.SshRsa);
        writer.WriteMPInt(e);
        writer.WriteMPInt(n);

        return new SshKey(AlgorithmNames.SshRsa, writer.ToArray());
    }

    public static RsaPublicKey CreateFromSshKey(ReadOnlyMemory<byte> key)
    {
        SequenceReader reader = new SequenceReader(key);
        reader.ReadName(AlgorithmNames.SshRsa);
        byte[] e = reader.ReadMPIntAsByteArray(isUnsigned: true);
        byte[] n = reader.ReadMPIntAsByteArray(isUnsigned: true);
        reader.ReadEnd();
        return new RsaPublicKey(e, n);
    }

    internal override bool VerifySignature(Name algorithmName, ReadOnlySpan<byte> data, ReadOnlySequence<byte> signature)
    {
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

        if (signature.Length != signatureLength)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }

        return rsa.VerifyData(data, signature.ToArray(), hashAlgorithm, RSASignaturePadding.Pkcs1);
    }
}
