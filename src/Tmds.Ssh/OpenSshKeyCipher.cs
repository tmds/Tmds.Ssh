// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class OpenSshKeyCipher
{
    private delegate byte[] DecryptDelegate(ReadOnlySpan<byte> key, Span<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> tag);

    private readonly DecryptDelegate _decryptData;

    private OpenSshKeyCipher(
        int keyLength,
        int ivLength,
        DecryptDelegate decryptData,
        bool isAuthenticated = false,
        int tagLength = 0)
    {
        KeyLength = keyLength;
        IVLength = ivLength;
        IsAuthenticated = isAuthenticated;
        TagLength = tagLength;
        _decryptData = decryptData;
    }

    public int KeyLength { get; }
    public int IVLength { get; }
    public bool IsAuthenticated { get; }
    public int TagLength { get; } // When IsAuthenticated == true

    public byte[] Decrypt(ReadOnlySpan<byte> key, Span<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> tag)
    {
        if (KeyLength != key.Length)
        {
            throw new ArgumentException(nameof(key));
        }
        if (IVLength != iv.Length)
        {
            throw new ArgumentException(nameof(iv));
        }
        if (IsAuthenticated && tag.Length != TagLength)
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
        };

    private static OpenSshKeyCipher CreateAesCbcCipher(int keyLength)
        => new OpenSshKeyCipher(keyLength: keyLength, ivLength: 16,
            (ReadOnlySpan<byte> key, Span<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> _)
                => DecryptCbc(key, iv, data));

    private static OpenSshKeyCipher CreateAesCtrCipher(int keyLength)
        => new OpenSshKeyCipher(keyLength: keyLength, ivLength: 16,
            (ReadOnlySpan<byte> key, Span<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> _)
                => AesCtr.DecryptCtr(key, iv, data));

    private static OpenSshKeyCipher CreateAesGcmCipher(int keyLength)
        => new OpenSshKeyCipher(keyLength: keyLength, ivLength: 12,
                DecryptGcm,
                isAuthenticated: true,
                tagLength: 16);

    private static byte[] DecryptCbc(ReadOnlySpan<byte> key, Span<byte> iv, ReadOnlySpan<byte> data)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();

        return aes.DecryptCbc(data, iv, PaddingMode.None);
    }

    public static byte[] DecryptGcm(ReadOnlySpan<byte> key, Span<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> tag)
    {
        using AesGcm aesGcm = new AesGcm(key, tag.Length);
        byte[] plaintext = new byte[data.Length];
        aesGcm.Decrypt(iv, data, tag, plaintext, null);
        return plaintext;
    }
}
