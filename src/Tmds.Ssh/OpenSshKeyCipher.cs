// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Tmds.Ssh;

sealed class OpenSshKeyCipher
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

    public static bool TryGetCipher(Name name, [NotNullWhen(true)] out OpenSshKeyCipher? ciphers)
        => _ciphers.TryGetValue(name, out ciphers);

    private static Dictionary<Name, OpenSshKeyCipher> _ciphers = new()
        {
            { AlgorithmNames.Aes128Cbc, CreateAesCbcCipher(16) },
            { AlgorithmNames.Aes192Cbc, CreateAesCbcCipher(24) },
            { AlgorithmNames.Aes256Cbc, CreateAesCbcCipher(32) },
            { AlgorithmNames.Aes128Ctr, CreateAesCtrCipher(16) },
            { AlgorithmNames.Aes192Ctr, CreateAesCtrCipher(24) },
            { AlgorithmNames.Aes256Ctr, CreateAesCtrCipher(32) },
            { AlgorithmNames.Aes128Gcm, CreateAesGcmCipher(16) },
            { AlgorithmNames.Aes256Gcm, CreateAesGcmCipher(32) },
            {AlgorithmNames.ChaCha20Poly1305,
                new OpenSshKeyCipher(
                    keyLength: 64,
                    ivLength: 0,
                    DecryptChaCha20Poly1305,
                    tagLength: 16) },
        };

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
