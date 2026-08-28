// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class HMacAlgorithm
{
    private readonly Func<HMacAlgorithm, byte[], IHMac> _create;

    private HMacAlgorithm(int keyLength, Func<HMacAlgorithm, byte[], IHMac> create)
    {
        KeyLength = keyLength;
        _create = create;
    }

    public int KeyLength { get; }

    public IHMac Create(byte[] key)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException(nameof(key));
        }
        return _create(this, key);
    }

    public static HMacAlgorithm Find(Name name)
    {
        // RFC 6668 defines hmac-sha2-256 and hmac-sha2-512.
        // The '-etm@openssh.com' variants use the same keys and hashes but apply the MAC
        // to the encrypted packet instead of the plaintext packet.
        if (name == AlgorithmNames.HMacSha2_256)
        {
            return Create(HashAlgorithmName.SHA256, 256 / 8, isEncryptThenMac: false);
        }
        else if (name == AlgorithmNames.HMacSha2_512)
        {
            return Create(HashAlgorithmName.SHA512, 512 / 8, isEncryptThenMac: false);
        }
        else if (name == AlgorithmNames.HMacSha2_256Etm)
        {
            return Create(HashAlgorithmName.SHA256, 256 / 8, isEncryptThenMac: true);
        }
        else if (name == AlgorithmNames.HMacSha2_512Etm)
        {
            return Create(HashAlgorithmName.SHA512, 512 / 8, isEncryptThenMac: true);
        }

        throw new NotSupportedException($"HMac algorithm '{name}' is not supported.");

        static HMacAlgorithm Create(HashAlgorithmName hashAlgorithm, int length, bool isEncryptThenMac)
            => new HMacAlgorithm(length, (algorithm, key) => new HMac(hashAlgorithm, length, length, key, isEncryptThenMac));
    }
}
