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
    {
        if (name == AlgorithmNames.Aes128Gcm)
        {
            return new PacketEncryptionAlgorithm(keyLength: 128 / 8, ivLength: 12,
                (PacketEncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                    => new AesGcmPacketEncryptor(key, iv, algorithm.TagLength),
                (PacketEncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                    => new AesGcmPacketDecryptor(sequencePool, key, iv, algorithm.TagLength),
                    isAuthenticated: true,
                    tagLength: 16);
        }
        else if (name == AlgorithmNames.Aes256Gcm)
        {
            return new PacketEncryptionAlgorithm(keyLength: 256 / 8, ivLength: 12,
                (PacketEncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                    => new AesGcmPacketEncryptor(key, iv, algorithm.TagLength),
                (PacketEncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                    => new AesGcmPacketDecryptor(sequencePool, key, iv, algorithm.TagLength),
                    isAuthenticated: true,
                    tagLength: 16);
        }
        else if (name == AlgorithmNames.ChaCha20Poly1305)
        {
            return new PacketEncryptionAlgorithm(keyLength: 512 / 8, ivLength: 0,
                (PacketEncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                    => new ChaCha20Poly1305PacketEncryptor(key),
                (PacketEncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                    => new ChaCha20Poly1305PacketDecryptor(sequencePool, key),
                    isAuthenticated: true,
                    tagLength: ChaCha20Poly1305PacketEncryptor.TagSize);
        }
        else if (name == AlgorithmNames.Aes128Ctr)
        {
            return CreateAesCtr(keyLength: 128 / 8);
        }
        else if (name == AlgorithmNames.Aes192Ctr)
        {
            return CreateAesCtr(keyLength: 192 / 8);
        }
        else if (name == AlgorithmNames.Aes256Ctr)
        {
            return CreateAesCtr(keyLength: 256 / 8);
        }

        throw new NotSupportedException($"Packet encryption algorithm '{name}' is not supported.");

        // aes[128|192|256]-ctr (RFC 4344) is not an authenticated cipher, it is combined with a MAC algorithm.
        static PacketEncryptionAlgorithm CreateAesCtr(int keyLength)
            => new PacketEncryptionAlgorithm(keyLength: keyLength, ivLength: AesCtrCryptoTransform.AesBlockSize,
                (PacketEncryptionAlgorithm algorithm, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                    => new TransformAndHMacPacketEncryptor(new AesCtrCryptoTransform(key, iv), CreateHMac(hmac, hmacKey)),
                (PacketEncryptionAlgorithm algorithm, SequencePool sequencePool, byte[] key, byte[] iv, HMacAlgorithm? hmac, byte[] hmacKey)
                    => new TransformAndHMacPacketDecryptor(sequencePool, new AesCtrCryptoTransform(key, iv), CreateHMac(hmac, hmacKey)));
    }

    private static IHMac CreateHMac(HMacAlgorithm? hmacAlgorithm, byte[] hmacKey)
    {
        if (hmacAlgorithm is null)
        {
            // A MAC algorithm is required for ciphers that are not authenticated.
            throw new ArgumentNullException(nameof(hmacAlgorithm));
        }
        return hmacAlgorithm.Create(hmacKey);
    }
}
