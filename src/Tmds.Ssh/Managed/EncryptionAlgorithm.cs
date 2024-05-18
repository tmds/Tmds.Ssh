// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Tmds.Ssh.Managed;

sealed class EncryptionAlgorithm
{
    private readonly Func<EncryptionAlgorithm, byte[], byte[], HMacAlgorithm?, byte[], IPacketEncoder> _createPacketEncoder;
    private readonly Func<EncryptionAlgorithm, SequencePool, byte[], byte[], HMacAlgorithm?, byte[], IPacketDecoder> _createPacketDecoder;

    private EncryptionAlgorithm(int keyLength, int ivLength,
            Func<EncryptionAlgorithm, byte[], byte[], HMacAlgorithm?, byte[], IPacketEncoder> createPacketEncoder,
            Func<EncryptionAlgorithm, SequencePool, byte[], byte[], HMacAlgorithm?, byte[], IPacketDecoder> createPacketDecoder,
            bool isAuthenticated = false,
            int tagLength = 0)
    {
        KeyLength = keyLength;
        IVLength = ivLength;
        IsAuthenticated = isAuthenticated;
        TagLength = tagLength;
        _createPacketEncoder = createPacketEncoder;
        _createPacketDecoder = createPacketDecoder;
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

    private static void CheckArguments(EncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmacAlgorithm, byte[] hmacKey)
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
            { AlgorithmNames.Aes128Gcm,
                new EncryptionAlgorithm(keyLength: 128 / 8, ivLength: 12,
                    (EncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketEncoder(key, iv, algorithm.TagLength),
                    (EncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketDecoder(sequencePool, key, iv, algorithm.TagLength),
                        isAuthenticated: true,
                        tagLength: 16) },
            { AlgorithmNames.Aes256Gcm,
                new EncryptionAlgorithm(keyLength: 256 / 8, ivLength: 12,
                    (EncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketEncoder(key, iv, algorithm.TagLength),
                    (EncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketDecoder(sequencePool, key, iv, algorithm.TagLength),
                        isAuthenticated: true,
                        tagLength: 16) },
        };

    private static IPacketEncoder CreatePacketEncoder(IDisposableCryptoTransform encodeTransform, IHMac hmac)
        => new TransformAndHMacPacketEncoder(encodeTransform, hmac);

    private static IPacketDecoder CreatePacketDecoder(SequencePool sequencePool, IDisposableCryptoTransform encodeTransform, IHMac hmac)
        => new TransformAndHMacPacketDecoder(sequencePool, encodeTransform, hmac);
}
