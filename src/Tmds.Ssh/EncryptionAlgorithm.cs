// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;

namespace Tmds.Ssh;

sealed class EncryptionAlgorithm
{
    private delegate byte[] DecryptDelegate(ReadOnlySpan<byte> key, Span<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> tag);

    private readonly Func<EncryptionAlgorithm, byte[], byte[], HMacAlgorithm?, byte[], IPacketEncoder> _createPacketEncoder;
    private readonly Func<EncryptionAlgorithm, SequencePool, byte[], byte[], HMacAlgorithm?, byte[], IPacketDecoder> _createPacketDecoder;
    private readonly DecryptDelegate _decryptData;

    private EncryptionAlgorithm(int keyLength, int ivLength,
            Func<EncryptionAlgorithm, byte[], byte[], HMacAlgorithm?, byte[], IPacketEncoder> createPacketEncoder,
            Func<EncryptionAlgorithm, SequencePool, byte[], byte[], HMacAlgorithm?, byte[], IPacketDecoder> createPacketDecoder,
            DecryptDelegate decryptData,
            bool isAuthenticated = false,
            int tagLength = 0)
    {
        KeyLength = keyLength;
        IVLength = ivLength;
        IsAuthenticated = isAuthenticated;
        TagLength = tagLength;
        _createPacketEncoder = createPacketEncoder;
        _createPacketDecoder = createPacketDecoder;
        _decryptData = decryptData;
    }

    public int KeyLength { get; }
    public int IVLength { get; }
    public bool IsAuthenticated { get; }
    public int TagLength { get; } // When IsAuthenticated == true

    public IPacketEncoder CreatePacketEncoder(byte[] key, byte[] iv, HMacAlgorithm? hmacAlgorithm, byte[] hmacKey)
    {
        CheckArguments(this, key, iv, hmacAlgorithm, hmacKey);
        return _createPacketEncoder(this, key, iv, hmacAlgorithm, hmacKey);
    }

    public IPacketDecoder CreatePacketDecoder(SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmacAlgorithm, byte[] hmacKey)
    {
        CheckArguments(this, key, iv, hmacAlgorithm, hmacKey);
        return _createPacketDecoder(this, sequencePool, key, iv, hmacAlgorithm, hmacKey);
    }

    public byte[] DecryptData(ReadOnlySpan<byte> key, Span<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> tag)
    {
        CheckArguments(this, key, iv, null, Array.Empty<byte>());
        if (IsAuthenticated && tag.Length != TagLength)
        {
            throw new ArgumentException(nameof(tag));
        }

        return _decryptData(key, iv, data, tag);
    }

    private static void CheckArguments(EncryptionAlgorithm algorithm, ReadOnlySpan<byte> key, Span<byte> iv, HMacAlgorithm? hmacAlgorithm, byte[] hmacKey)
    {
        if (algorithm.IVLength != iv.Length)
        {
            throw new ArgumentException(nameof(iv));
        }
        if (algorithm.KeyLength != key.Length)
        {
            throw new ArgumentException(nameof(key));
        }
        if (algorithm.IsAuthenticated && hmacAlgorithm is not null)
        {
            throw new ArgumentException(nameof(hmacAlgorithm));
        }
        if (hmacAlgorithm is null && hmacKey.Length > 0)
        {
            throw new ArgumentException(nameof(hmacKey));
        }
    }

    public static EncryptionAlgorithm Find(Name name)
        => _algorithms[name];

    private static Dictionary<Name, EncryptionAlgorithm> _algorithms = new()
        {
            { AlgorithmNames.Aes128Cbc, CreateAesCbcAlgorithm(16) },
            { AlgorithmNames.Aes192Cbc, CreateAesCbcAlgorithm(24) },
            { AlgorithmNames.Aes256Cbc, CreateAesCbcAlgorithm(32) },
            { AlgorithmNames.Aes128Ctr, CreateAesCtrAlgorithm(16) },
            { AlgorithmNames.Aes192Ctr, CreateAesCtrAlgorithm(24) },
            { AlgorithmNames.Aes256Ctr, CreateAesCtrAlgorithm(32) },
            { AlgorithmNames.Aes128Gcm, CreateAesGcmAlgorithm(16) },
            { AlgorithmNames.Aes256Gcm, CreateAesGcmAlgorithm(32) },
            { AlgorithmNames.ChaCha20Poly1305,
                new EncryptionAlgorithm(keyLength: 64, ivLength: 0,
                    (EncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => throw new NotImplementedException(),
                    (EncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => throw new NotImplementedException(),
                    (ReadOnlySpan<byte> key, Span<byte> _1, ReadOnlySpan<byte> data, ReadOnlySpan<byte> _2)
                        => ChaCha20Decrypter.Decrypt(key[..32], data)) },
        };

    private static EncryptionAlgorithm CreateAesCbcAlgorithm(int keyLength)
        => new EncryptionAlgorithm(keyLength: keyLength, ivLength: 16,
            (EncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                => throw new NotImplementedException(),
            (EncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                => throw new NotImplementedException(),
            (ReadOnlySpan<byte> key, Span<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> _)
                => AesDecrypter.DecryptCbc(key, iv, data));

    private static EncryptionAlgorithm CreateAesCtrAlgorithm(int keyLength)
        => new EncryptionAlgorithm(keyLength: keyLength, ivLength: 16,
            (EncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                => throw new NotImplementedException(),
            (EncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                => throw new NotImplementedException(),
            (ReadOnlySpan<byte> key, Span<byte> iv, ReadOnlySpan<byte> data, ReadOnlySpan<byte> _)
                => AesDecrypter.DecryptCtr(key, iv, data));

    private static EncryptionAlgorithm CreateAesGcmAlgorithm(int keyLength)
        => new EncryptionAlgorithm(keyLength: keyLength, ivLength: 12,
            (EncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                => new AesGcmPacketEncoder(key, iv, algorithm.TagLength),
            (EncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                => new AesGcmPacketDecoder(sequencePool, key, iv, algorithm.TagLength),
                AesDecrypter.DecryptGcm,
                isAuthenticated: true,
                tagLength: 16);

    private static IPacketEncoder CreatePacketEncoder(IDisposableCryptoTransform encodeTransform, IHMac hmac)
        => new TransformAndHMacPacketEncoder(encodeTransform, hmac);

    private static IPacketDecoder CreatePacketDecoder(SequencePool sequencePool, IDisposableCryptoTransform encodeTransform, IHMac hmac)
        => new TransformAndHMacPacketDecoder(sequencePool, encodeTransform, hmac);
}
