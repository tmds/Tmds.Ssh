// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;

namespace Tmds.Ssh;

sealed class PackingAlgorithms
{
    private readonly Func<PackingAlgorithms, byte[], byte[], HMacAlgorithm?, byte[], IPacketEncoder> _createPacketEncoder;
    private readonly Func<PackingAlgorithms, SequencePool, byte[], byte[], HMacAlgorithm?, byte[], IPacketDecoder> _createPacketDecoder;

    private PackingAlgorithms(int keyLength, int ivLength,
            Func<PackingAlgorithms, byte[], byte[], HMacAlgorithm?, byte[], IPacketEncoder> createPacketEncoder,
            Func<PackingAlgorithms, SequencePool, byte[], byte[], HMacAlgorithm?, byte[], IPacketDecoder> createPacketDecoder,
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

    private static void CheckArguments(PackingAlgorithms algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmacAlgorithm, byte[] hmacKey)
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

    public static PackingAlgorithms Find(Name name)
        => _algorithms[name];

    private static Dictionary<Name, PackingAlgorithms> _algorithms = new()
        {
            { AlgorithmNames.Aes128Gcm,
                new PackingAlgorithms(keyLength: 128 / 8, ivLength: 12,
                    (PackingAlgorithms algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketEncoder(key, iv, algorithm.TagLength),
                    (PackingAlgorithms algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketDecoder(sequencePool, key, iv, algorithm.TagLength),
                        isAuthenticated: true,
                        tagLength: 16) },
            { AlgorithmNames.Aes256Gcm,
                new PackingAlgorithms(keyLength: 256 / 8, ivLength: 12,
                    (PackingAlgorithms algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketEncoder(key, iv, algorithm.TagLength),
                    (PackingAlgorithms algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketDecoder(sequencePool, key, iv, algorithm.TagLength),
                        isAuthenticated: true,
                        tagLength: 16) },
        };
}