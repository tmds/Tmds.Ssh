// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;

namespace Tmds.Ssh;

partial class PrivateKeyParser
{
    /// <summary>
    /// Parses an OpenSSH PEM formatted key. This is a new key format used by
    /// OpenSSH for private keys.
    /// </summary>
    internal static bool TryParseOpenSshKey(
        byte[] keyData,
        ReadOnlySpan<byte> password,
        [NotNullWhen(true)] out PrivateKey? privateKey,
        [NotNullWhen(false)] out Exception? error)
    {
        privateKey = null;

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
            error = new FormatException($"Unknown OpenSSH key format.");
            return false;
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
            error = new FormatException($"The data contains multiple keys.");
            return false; // Multiple keys are not supported.
        }
        reader.SkipString(); // skip the public key
        ReadOnlySequence<byte> privateKeyList;
        if (cipherName == AlgorithmNames.None)
        {
            privateKeyList = reader.ReadStringAsBytes();
        }
        else if (password.Length == 0)
        {
            error = new FormatException("Key was encrypted but no password was provided.");
            return false;
        }
        else
        {
            if (!TryDecryptOpenSshPrivateKey(reader, cipherName, kdfName, kdfOptions, password, out var decryptedKey, out error))
            {
                return false;
            }
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
            error = new FormatException($"The checkints mismatch. The key is invalid or the password is wrong.");
            return false;
        }

        Name keyType = reader.ReadName();
        if (keyType == AlgorithmNames.SshRsa)
        {
            return TryParseOpenSshRsaKey(reader, out privateKey, out error);
        }
        if (keyType.ToString().StartsWith("ecdsa-sha2-"))
        {
            return TryParseOpenSshEcdsaKey(keyType, reader, out privateKey, out error);
        }
        else
        {
            error = new NotSupportedException($"The key type is unsupported: '{keyType}'.");
            return false;
        }
    }

    private static bool TryDecryptOpenSshPrivateKey(
        SequenceReader reader,
        Name cipher,
        Name kdf,
        ReadOnlySequence<byte> kdfOptions,
        ReadOnlySpan<byte> password,
        [NotNullWhen(true)] out byte[]? privateKey,
        [NotNullWhen(false)] out Exception? error)
    {
        privateKey = null;

        if (kdf != AlgorithmNames.BCrypt)
        {
            error = new NotSupportedException($"Unsupported KDF: '{kdf}'.");
            return false;
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
            error = new NotSupportedException($"Unsupported Cipher: '{cipher}'.");
            return false;
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
            if (keyCipher.IsAuthenticated && keyCipher.TagLength > 0)
            {
                if (!reader.TryRead(keyCipher.TagLength, out tag))
                {
                    error = new FormatException($"Failed to read {cipher} encryption tag for encrypted OpenSSH key.");
                    return false;
                }
            }

            privateKey = keyCipher.Decrypt(
                derivedKey.AsSpan(0, keyCipher.KeyLength),
                derivedKey.AsSpan(keyCipher.KeyLength, keyCipher.IVLength),
                encryptedKey.IsSingleSegment ? encryptedKey.FirstSpan : encryptedKey.ToArray(),
                tag.IsSingleSegment ? tag.FirstSpan : tag.ToArray());
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = new FormatException($"Failed to decrypt OpenSSH key with cipher {cipher}.", ex);
            return false;
        }
    }

    private static bool TryParseOpenSshRsaKey(SequenceReader reader, [NotNullWhen(true)] out PrivateKey? privateKey, [NotNullWhen(false)] out Exception? error)
    {
        privateKey = null;

        byte[] modulus = reader.ReadMPIntAsByteArray(isUnsigned: true);
        byte[] exponent = reader.ReadMPIntAsByteArray(isUnsigned: true);
        BigInteger d = reader.ReadMPInt();
        byte[] inverseQ = reader.ReadMPIntAsByteArray(isUnsigned: true);
        BigInteger p = reader.ReadMPInt();
        BigInteger q = reader.ReadMPInt();

        BigInteger dp = d % (p - BigInteger.One);
        BigInteger dq = d % (q - BigInteger.One);

        RSAParameters parameters = new()
        {
            Modulus = modulus,
            Exponent = exponent,
            D = d.ToByteArray(isUnsigned: true, isBigEndian: true),
            InverseQ = inverseQ,
            P = p.ToByteArray(isUnsigned: true, isBigEndian: true),
            Q = q.ToByteArray(isUnsigned: true, isBigEndian: true),
            DP = dp.ToByteArray(isUnsigned: true, isBigEndian: true),
            DQ = dq.ToByteArray(isUnsigned: true, isBigEndian: true)
        };
        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportParameters(parameters);
            privateKey = new RsaPrivateKey(rsa);
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = new FormatException($"The data can not be parsed into an RSA key.", ex);
            rsa.Dispose();
            return false;
        }
    }

    private static bool TryParseOpenSshEcdsaKey(Name keyIdentifier, SequenceReader reader, [NotNullWhen(true)] out PrivateKey? privateKey, [NotNullWhen(false)] out Exception? error)
    {
        privateKey = null;

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
            error = new NotSupportedException($"ECDSA curve '{curveName}' is unsupported.");
            return false;
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
            privateKey = new ECDsaPrivateKey(ecdsa, keyIdentifier, curveName, allowedHashAlgo);
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = new FormatException($"The data can not be parsed into an ECDSA key.", ex);
            ecdsa.Dispose();
            return false;
        }
    }
}
