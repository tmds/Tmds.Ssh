// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// POCO https://tools.ietf.org/html/rfc4253#section-7.2
sealed class KeyExchangeOutput
{
    public KeyExchangeOutput(byte[] exchangeHash,
        byte[] initialIVS2C, byte[] encryptionKeyS2C, byte[] integrityKeyS2C,
        byte[] initialIVC2S, byte[] encryptionKeyC2S, byte[] integrityKeyC2S)
    {
        ExchangeHash = exchangeHash ?? throw new ArgumentException(nameof(exchangeHash));
        InitialIVS2C = initialIVS2C ?? throw new ArgumentException(nameof(initialIVS2C));
        EncryptionKeyS2C = encryptionKeyS2C ?? throw new ArgumentException(nameof(encryptionKeyS2C));
        IntegrityKeyS2C = integrityKeyS2C ?? throw new ArgumentException(nameof(integrityKeyS2C));
        InitialIVC2S = initialIVC2S ?? throw new ArgumentException(nameof(initialIVC2S));
        EncryptionKeyC2S = encryptionKeyC2S ?? throw new ArgumentException(nameof(encryptionKeyC2S));
        IntegrityKeyC2S = integrityKeyC2S ?? throw new ArgumentException(nameof(integrityKeyC2S));
    }

    public byte[] ExchangeHash { get; }
    public byte[] InitialIVS2C { get; }
    public byte[] EncryptionKeyS2C { get; }
    public byte[] IntegrityKeyS2C { get; }
    public byte[] InitialIVC2S { get; }
    public byte[] EncryptionKeyC2S { get; }
    public byte[] IntegrityKeyC2S { get; }
}
