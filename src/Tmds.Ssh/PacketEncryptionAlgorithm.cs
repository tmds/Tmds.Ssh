// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

sealed class PacketEncryptionAlgorithm
{
    private readonly Func<PacketEncryptionAlgorithm, byte[], byte[], HMacAlgorithm?, byte[], IPacketEncryptor> _createPacketEncryptor;
    private readonly Func<PacketEncryptionAlgorithm, SequencePool, byte[], byte[], HMacAlgorithm?, byte[], IPacketDecryptor> _createPacketDecryptor;

    private PacketEncryptionAlgorithm(int keyLength, int ivLength,
            Func<PacketEncryptionAlgorithm, byte[], byte[], HMacAlgorithm?, byte[], IPacketEncryptor> createPacketEncryptor,
            Func<PacketEncryptionAlgorithm, SequencePool, byte[], byte[], HMacAlgorithm?, byte[], IPacketDecryptor> createPacketDecryptor,
            bool isAuthenticated = false,
            int tagLength = 0)
    {
        KeyLength = keyLength;
        IVLength = ivLength;
        TagLength = tagLength;
        _createPacketEncryptor = createPacketEncryptor;
        _createPacketDecryptor = createPacketDecryptor;
    }

    public int KeyLength { get; }
    public int IVLength { get; }
    public bool IsAuthenticated => TagLength > 0;
    private int TagLength { get; }

    public IPacketEncryptor CreatePacketEncryptor(byte[] key, byte[] iv, HMacAlgorithm? hmacAlgorithm, byte[] hmacKey)
    {
        CheckArguments(this, key, iv, hmacAlgorithm, hmacKey);
        return _createPacketEncryptor(this, key, iv, hmacAlgorithm, hmacKey);
    }

    public IPacketDecryptor CreatePacketDecryptor(SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmacAlgorithm, byte[] hmacKey)
    {
        CheckArguments(this, key, iv, hmacAlgorithm, hmacKey);
        return _createPacketDecryptor(this, sequencePool, key, iv, hmacAlgorithm, hmacKey);
    }

    private static void CheckArguments(PacketEncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmacAlgorithm, byte[] hmacKey)
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

    public static PacketEncryptionAlgorithm Find(Name name)
        => _algorithms[name];

    private static Dictionary<Name, PacketEncryptionAlgorithm> _algorithms = new()
        {
            { AlgorithmNames.Aes128Gcm,
                new PacketEncryptionAlgorithm(keyLength: 128 / 8, ivLength: 12,
                    (PacketEncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketEncryptor(key, iv, algorithm.TagLength),
                    (PacketEncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketDecryptor(sequencePool, key, iv, algorithm.TagLength),
                        isAuthenticated: true,
                        tagLength: 16) },
            { AlgorithmNames.Aes256Gcm,
                new PacketEncryptionAlgorithm(keyLength: 256 / 8, ivLength: 12,
                    (PacketEncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketEncryptor(key, iv, algorithm.TagLength),
                    (PacketEncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new AesGcmPacketDecryptor(sequencePool, key, iv, algorithm.TagLength),
                        isAuthenticated: true,
                        tagLength: 16) },
            { AlgorithmNames.ChaCha20Poly1305,
                new PacketEncryptionAlgorithm(keyLength: 512 / 8, ivLength: 0,
                    (PacketEncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new ChaCha20Poly1305PacketEncryptor(key),
                    (PacketEncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                        => new ChaCha20Poly1305PacketDecryptor(sequencePool, key),
                        isAuthenticated: true,
                        tagLength: ChaCha20Poly1305PacketEncryptor.TagSize) },
        };
}
