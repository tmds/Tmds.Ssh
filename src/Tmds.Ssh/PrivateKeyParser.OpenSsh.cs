// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Tmds.Ssh;

partial class PrivateKeyParser
{
    /// <summary>
    /// Parses an OpenSSH PEM formatted key. This is a new key format used by
    /// OpenSSH for private keys.
    /// </summary>
    internal static PrivateKey ParseOpenSshKey(
        byte[] keyData,
        Func<string?> passwordPrompt)
    {
        // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
        /*
            byte[]	AUTH_MAGIC
            string	ciphername
            string	kdfname
            string	kdfoptions
            uint32	number of keys N
            string	publickey1
            string	publickey2
            ...
            string	publickeyN
            string	encrypted, padded list of private keys
        */
        ReadOnlySpan<byte> AUTH_MAGIC = "openssh-key-v1\0"u8;
        if (!keyData.AsSpan().StartsWith(AUTH_MAGIC))
        {
            throw new FormatException($"Unknown OpenSSH key format.");
        }
        ReadOnlySequence<byte> ros = new ReadOnlySequence<byte>(keyData);
        ros = ros.Slice(AUTH_MAGIC.Length);
        var reader = new SequenceReader(ros);
        Name cipherName = reader.ReadName();
        Name kdfName = reader.ReadName();
        ReadOnlySequence<byte> kdfOptions = reader.ReadStringAsBytes();
        uint nrOfKeys = reader.ReadUInt32();
        if (nrOfKeys != 1)
        {
            throw new FormatException($"The data contains multiple keys.");
        }
        byte[] publicKey = reader.ReadStringAsByteArray();
        ReadOnlySequence<byte> privateKeyList;
        if (cipherName == AlgorithmNames.None)
        {
            privateKeyList = reader.ReadStringAsBytes();
        }
        else
        {
            string? password = passwordPrompt();
            if (password is null)
            {
                throw new FormatException("Key was encrypted but no password was provided.");
            }

            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] decryptedKey = DecryptOpenSshPrivateKey(reader, cipherName, kdfName, kdfOptions, passwordBytes);
            privateKeyList = new ReadOnlySequence<byte>(decryptedKey);
        }

        reader = new SequenceReader(privateKeyList);
        /*
            uint32	checkint
            uint32	checkint
            byte[]	privatekey1
            string	comment1
            byte[]	privatekey2
            string	comment2
            ...
            byte[]	privatekeyN
            string	commentN
            byte	1
            byte	2
            byte	3
            ...
            byte	padlen % 255
        */
        uint checkInt1 = reader.ReadUInt32();
        uint checkint2 = reader.ReadUInt32();
        if (checkInt1 != checkint2)
        {
            throw new FormatException($"The checkints mismatch. The key is invalid or the password is wrong.");
        }

        Name keyType = reader.ReadName();
        if (keyType == AlgorithmNames.SshRsa)
        {
            return ParseOpenSshRsaKey(publicKey, reader);
        }
        else if (keyType.ToString().StartsWith("ecdsa-sha2-"))
        {
            return ParseOpenSshEcdsaKey(publicKey, keyType, reader);
        }
        else if (keyType == AlgorithmNames.SshEd25519)
        {
            return ParseOpenSshEd25519Key(publicKey, reader);
        }
        else
        {
            throw new NotSupportedException($"The key type is unsupported: '{keyType}'.");
        }
    }

    private static byte[] DecryptOpenSshPrivateKey(
        SequenceReader reader,
        Name cipher,
        Name kdf,
        ReadOnlySequence<byte> kdfOptions,
        ReadOnlySpan<byte> password)
    {
        if (kdf != AlgorithmNames.BCrypt)
        {
            throw new NotSupportedException($"Unsupported KDF: '{kdf}'.");
        }

        /*
            string salt
            uint32 rounds
        */
        var kdfReader = new SequenceReader(kdfOptions);
        ReadOnlySequence<byte> kdfSalt = kdfReader.ReadStringAsBytes();
        uint rounds = kdfReader.ReadUInt32();

        if (!OpenSshKeyCipher.TryGetCipher(cipher, out var keyCipher))
        {
            throw new NotSupportedException($"Unsupported Cipher: '{cipher}'.");
        }

        try
        {
            byte[] derivedKey = new byte[keyCipher.KeyLength + keyCipher.IVLength];
            BCrypt.DeriveKeyFromPassword(
                password,
                kdfSalt.IsSingleSegment ? kdfSalt.FirstSpan : kdfSalt.ToArray(),
                (int)rounds,
                derivedKey);

            ReadOnlySequence<byte> encryptedKey = reader.ReadStringAsBytes();
            ReadOnlySequence<byte> tag = default;
            if (keyCipher.TagLength > 0)
            {
                if (!reader.TryRead(keyCipher.TagLength, out tag))
                {
                    throw new FormatException($"Failed to read {cipher} encryption tag for encrypted OpenSSH key.");
                }
            }

            return keyCipher.Decrypt(
                derivedKey.AsSpan(0, keyCipher.KeyLength),
                derivedKey.AsSpan(keyCipher.KeyLength, keyCipher.IVLength),
                encryptedKey.IsSingleSegment ? encryptedKey.FirstSpan : encryptedKey.ToArray(),
                tag.IsSingleSegment ? tag.FirstSpan : tag.ToArray());
        }
        catch (Exception ex)
        {
            throw new FormatException($"Failed to decrypt OpenSSH key with cipher {cipher}.", ex);
        }
    }

    private static PrivateKey ParseOpenSshRsaKey(byte[] publicKey, SequenceReader reader)
    {
        // .NET RSA's class has some length expectations:
        // D must have the same length as Modulus.
        // P, Q, DP, DQ, and InverseQ must have half the length of Modulus rounded up.
        byte[] modulus = reader.ReadMPIntAsByteArray(isUnsigned: true);
        int halfLength = (modulus.Length + 1) / 2;
        byte[] exponent = reader.ReadMPIntAsByteArray(isUnsigned: true);
        BigInteger d = reader.ReadMPInt();
        byte[] inverseQ = reader.ReadMPIntAsByteArray(isUnsigned: true, minLength: halfLength);
        BigInteger p = reader.ReadMPInt();
        BigInteger q = reader.ReadMPInt();

        BigInteger dp = d % (p - BigInteger.One);
        BigInteger dq = d % (q - BigInteger.One);

        RSAParameters parameters = new()
        {
            Modulus = modulus,
            Exponent = exponent,
            D = d.ToBEByteArray(isUnsigned: true, minLength: modulus.Length),
            InverseQ = inverseQ,

            P = p.ToBEByteArray(isUnsigned: true, minLength: halfLength),
            Q = q.ToBEByteArray(isUnsigned: true, minLength: halfLength),
            DP = dp.ToBEByteArray(isUnsigned: true, minLength: halfLength),
            DQ = dq.ToBEByteArray(isUnsigned: true, minLength: halfLength)
        };
        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportParameters(parameters);
            return new RsaPrivateKey(rsa, new SshKey(AlgorithmNames.SshRsa, publicKey));
        }
        catch (Exception ex)
        {
            rsa.Dispose();
            throw new FormatException($"The data can not be parsed into an RSA key.", ex);
        }
    }

    private static PrivateKey ParseOpenSshEcdsaKey(byte[] publicKey, Name keyType, SequenceReader reader)
    {
        Name curveName = reader.ReadName();

        HashAlgorithmName allowedHashAlgo;
        ECCurve curve;
        if (curveName == AlgorithmNames.Nistp256)
        {
            allowedHashAlgo = HashAlgorithmName.SHA256;
            curve = ECCurve.NamedCurves.nistP256;
        }
        else if (curveName == AlgorithmNames.Nistp384)
        {
            allowedHashAlgo = HashAlgorithmName.SHA384;
            curve = ECCurve.NamedCurves.nistP384;
        }
        else if (curveName == AlgorithmNames.Nistp521)
        {
            allowedHashAlgo = HashAlgorithmName.SHA512;
            curve = ECCurve.NamedCurves.nistP521;
        }
        else
        {
            throw new NotSupportedException($"ECDSA curve '{curveName}' is unsupported.");
        }

        ECPoint q = reader.ReadStringAsECPoint();
        byte[] d = reader.ReadMPIntAsByteArray(isUnsigned: true, minLength: q.X!.Length);

        ECDsa ecdsa = ECDsa.Create();
        try
        {
            ECParameters parameters = new()
            {
                Curve = curve,
                Q = q,
                D = d
            };

            ecdsa.ImportParameters(parameters);
            return new ECDsaPrivateKey(ecdsa, keyType, curveName, allowedHashAlgo, new SshKey(keyType, publicKey));
        }
        catch (Exception ex)
        {
            ecdsa.Dispose();
            throw new FormatException($"The data can not be parsed into an ECDSA key.", ex);
        }
    }

    private static PrivateKey ParseOpenSshEd25519Key(byte[] sshPublicKey, SequenceReader reader)
    {
        // https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-14#section-3.2.3
        /*
            string           ENC(A)
            string           k || ENC(A)

        The first value is the EDDSA public key ENC(A). The second value is a
        concatenation of the private key k and the public ENC(A) key. Why it is
        repeated, I have no idea.
        */

        try
        {
            ReadOnlySequence<byte> publicKey = reader.ReadStringAsBytes();
            ReadOnlySequence<byte> keyData = reader.ReadStringAsBytes();

            return new Ed25519PrivateKey(
                keyData.Slice(0, keyData.Length - publicKey.Length).ToArray(),
                publicKey.ToArray(),
                new SshKey(AlgorithmNames.SshEd25519, sshPublicKey));
        }
        catch (Exception ex)
        {
            throw new FormatException($"The data can not be parsed into an ED25519 key.", ex);
        }
    }
}
