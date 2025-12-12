// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Tmds.Ssh;

partial class PrivateKeyParser
{
    /// <summary>
    /// Parses an OpenSSH PEM formatted key. This is a new key format used by
    /// OpenSSH for private keys.
    /// </summary>
    internal static (SshKeyData PublicKey, bool isEncrypted, PrivateKey? PrivateKey) ParseOpenSshKey(
        ReadOnlyMemory<byte> keyData,
        Func<string?> passwordPrompt,
        bool parsePrivate)
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
        if (!keyData.Span.StartsWith(AUTH_MAGIC))
        {
            throw new NotSupportedException($"Unknown OpenSSH key format.");
        }
        ReadOnlySequence<byte> ros = new ReadOnlySequence<byte>(keyData);
        ros = ros.Slice(AUTH_MAGIC.Length);
        var reader = new SequenceReader(ros);
        Name cipherName = reader.ReadName();
        bool isEncrypted = cipherName != AlgorithmNames.None;
        Name kdfName = reader.ReadName();
        ReadOnlySequence<byte> kdfOptions = reader.ReadStringAsBytes();
        uint nrOfKeys = reader.ReadUInt32();
        if (nrOfKeys != 1)
        {
            throw new InvalidDataException($"The data contains multiple keys.");
        }

        SshKeyData publicKey = reader.ReadSshKey();
        if (!parsePrivate)
        {
            return (publicKey, isEncrypted, null);
        }

        ReadOnlySequence<byte> privateKeyList;
        if (!isEncrypted)
        {
            privateKeyList = reader.ReadStringAsBytes();
        }
        else
        {
            string? password = passwordPrompt();
            if (password is null)
            {
                throw new CryptographicException("Key is encrypted but no password was provided.");
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
            throw new CryptographicException($"The checkints mismatch. The key is invalid or the password is wrong.");
        }

        Name keyType = reader.ReadName();
        if (keyType == AlgorithmNames.SshRsa)
        {
            return (publicKey, isEncrypted, ParseOpenSshRsaKey(publicKey, reader));
        }
        else if (keyType.ToString().StartsWith("ecdsa-sha2-"))
        {
            return (publicKey, isEncrypted, ParseOpenSshEcdsaKey(publicKey, keyType, reader));
        }
        else if (keyType == AlgorithmNames.SshEd25519)
        {
            return (publicKey, isEncrypted, ParseOpenSshEd25519Key(publicKey, reader));
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
            if (!reader.TryRead(keyCipher.TagLength, out ReadOnlySequence<byte> tag))
            {
                throw new InvalidDataException($"Failed to read encryption tag.");
            }

            return keyCipher.Decrypt(
                derivedKey.AsSpan(0, keyCipher.KeyLength),
                derivedKey.AsSpan(keyCipher.KeyLength, keyCipher.IVLength),
                encryptedKey.IsSingleSegment ? encryptedKey.FirstSpan : encryptedKey.ToArray(),
                tag.IsSingleSegment ? tag.FirstSpan : tag.ToArray());
        }
        catch (Exception ex)
        {
            throw new CryptographicException($"Failed to decrypt OpenSSH key with cipher {cipher}.", ex);
        }
    }

    private static PrivateKey ParseOpenSshRsaKey(SshKeyData publicKey, SequenceReader reader)
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
            return new RsaPrivateKey(rsa, publicKey);
        }
        catch (Exception ex)
        {
            rsa.Dispose();
            throw new InvalidDataException($"The data can not be parsed into an RSA key.", ex);
        }
    }

    private static PrivateKey ParseOpenSshEcdsaKey(SshKeyData publicKey, Name keyType, SequenceReader reader)
    {
        Name curveName = reader.ReadName();

        HashAlgorithmName hashAlgorithm;
        ECCurve curve;
        if (curveName == AlgorithmNames.Nistp256)
        {
            hashAlgorithm = HashAlgorithmName.SHA256;
            curve = ECCurve.NamedCurves.nistP256;
        }
        else if (curveName == AlgorithmNames.Nistp384)
        {
            hashAlgorithm = HashAlgorithmName.SHA384;
            curve = ECCurve.NamedCurves.nistP384;
        }
        else if (curveName == AlgorithmNames.Nistp521)
        {
            hashAlgorithm = HashAlgorithmName.SHA512;
            curve = ECCurve.NamedCurves.nistP521;
        }
        else
        {
            throw new NotSupportedException($"Unsupported ECDSA curve: '{curveName}'.");
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
            return new ECDsaPrivateKey(ecdsa, keyType, curveName, hashAlgorithm, publicKey);
        }
        catch (Exception ex)
        {
            ecdsa.Dispose();
            throw new InvalidDataException($"The data can not be parsed into an ECDSA key.", ex);
        }
    }

    private static PrivateKey ParseOpenSshEd25519Key(SshKeyData sshPublicKey, SequenceReader reader)
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
                sshPublicKey);
        }
        catch (Exception ex)
        {
            throw new InvalidDataException($"The data can not be parsed into an ED25519 key.", ex);
        }
    }

    private sealed class OpenSshKeyCipher
    {
        private delegate byte[] DecryptDelegate(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> tag);

        private readonly DecryptDelegate _decryptData;

        private OpenSshKeyCipher(
            int keyLength,
            int ivLength,
            DecryptDelegate decryptData,
            int tagLength = 0)
        {
            KeyLength = keyLength;
            IVLength = ivLength;
            TagLength = tagLength;
            _decryptData = decryptData;
        }

        public int KeyLength { get; }
        public int IVLength { get; }
        public int TagLength { get; }

        public byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> tag)
        {
            if (KeyLength != key.Length)
            {
                throw new ArgumentException(nameof(key));
            }
            if (IVLength != iv.Length)
            {
                throw new ArgumentException(nameof(iv));
            }
            if (tag.Length != TagLength)
            {
                throw new ArgumentException(nameof(tag));
            }

            return _decryptData(key, iv, data, tag);
        }

        public static bool TryGetCipher(Name name, [NotNullWhen(true)] out OpenSshKeyCipher? cipher)
        {
            if (name == AlgorithmNames.Aes128Cbc)
            {
                cipher = CreateAesCbcCipher(16);
                return true;
            }
            else if (name == AlgorithmNames.Aes192Cbc)
            {
                cipher = CreateAesCbcCipher(24);
                return true;
            }
            else if (name == AlgorithmNames.Aes256Cbc)
            {
                cipher = CreateAesCbcCipher(32);
                return true;
            }
            else if (name == AlgorithmNames.Aes128Ctr)
            {
                cipher = CreateAesCtrCipher(16);
                return true;
            }
            else if (name == AlgorithmNames.Aes192Ctr)
            {
                cipher = CreateAesCtrCipher(24);
                return true;
            }
            else if (name == AlgorithmNames.Aes256Ctr)
            {
                cipher = CreateAesCtrCipher(32);
                return true;
            }
            else if (name == AlgorithmNames.Aes128Gcm)
            {
                cipher = CreateAesGcmCipher(16);
                return true;
            }
            else if (name == AlgorithmNames.Aes256Gcm)
            {
                cipher = CreateAesGcmCipher(32);
                return true;
            }
            else if (name == AlgorithmNames.ChaCha20Poly1305)
            {
                cipher = new OpenSshKeyCipher(
                    keyLength: 64,
                    ivLength: 0,
                    DecryptChaCha20Poly1305,
                    tagLength: 16);
                return true;
            }

            cipher = null;
            return false;
        }

        private static OpenSshKeyCipher CreateAesCbcCipher(int keyLength)
            => new OpenSshKeyCipher(keyLength: keyLength, ivLength: 16,
                (ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> _)
                    => DecryptAesCbc(key, iv, data));

        private static OpenSshKeyCipher CreateAesCtrCipher(int keyLength)
            => new OpenSshKeyCipher(keyLength: keyLength, ivLength: 16,
                (ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> _)
                    => DecryptAesCtr(key, iv, data));

        private static OpenSshKeyCipher CreateAesGcmCipher(int keyLength)
            => new OpenSshKeyCipher(keyLength: keyLength, ivLength: 12,
                DecryptAesGcm,
                tagLength: 16);

        private static byte[] DecryptAesCbc(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
        {
            using Aes aes = Aes.Create();
            aes.Key = key.ToArray();
            return aes.DecryptCbc(data, iv, PaddingMode.None);
        }

        private static byte[] DecryptAesCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
        {
            byte[] plaintext = new byte[data.Length];
            AesCtr.DecryptCtr(key, iv, data, plaintext);
            return plaintext;
        }

        private static byte[] DecryptAesGcm(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> tag)
        {
            using AesGcm aesGcm = new AesGcm(key, tag.Length);
            byte[] plaintext = new byte[data.Length];
            aesGcm.Decrypt(iv, data, tag, plaintext, null);
            return plaintext;
        }

        private static byte[] DecryptChaCha20Poly1305(ReadOnlySpan<byte> key, ReadOnlySpan<byte> _, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
        {
            ReadOnlySpan<byte> iv = stackalloc byte[12];
            ReadOnlySpan<byte> K_1 = key[..32];

            ChaCha7539Engine chacha = new();
            chacha.Init(forEncryption: false, new ParametersWithIV(new KeyParameter(K_1), iv));

            // Calculate poly key
            Span<byte> polyKey = stackalloc byte[64];
            chacha.ProcessBytes(input: polyKey, output: polyKey);

            // Calculate mac
            Poly1305 poly = new();
            poly.Init(new KeyParameter(polyKey[..32]));
            poly.BlockUpdate(ciphertext);
            Span<byte> ciphertextTag = stackalloc byte[16];
            poly.DoFinal(ciphertextTag);

            // Check mac
            if (!CryptographicOperations.FixedTimeEquals(ciphertextTag, tag))
            {
                throw new CryptographicException();
            }

            // Decode plaintext
            byte[] plaintext = new byte[ciphertext.Length];
            chacha.ProcessBytes(ciphertext, plaintext);

            return plaintext;
        }
    }
}
