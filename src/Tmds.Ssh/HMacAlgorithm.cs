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
        if (name == AlgorithmNames.HMacSha2_256)
        {
            return new HMacAlgorithm(256 / 8, (algorithm, key) => new HMac(HashAlgorithmName.SHA256, 256 / 8, 256 / 8, key));
        }

        throw new NotSupportedException($"HMac algorithm '{name}' is not supported.");
    }
}
