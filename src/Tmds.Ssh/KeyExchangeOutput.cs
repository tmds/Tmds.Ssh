// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // POCO https://tools.ietf.org/html/rfc4253#section-7.2
    sealed class KeyExchangeOutput
    {
        public KeyExchangeOutput(byte[] exchangeHash, byte[] initialIV, byte[] encryptionKey, byte[] integrityKey)
        {
            ExchangeHash = exchangeHash ?? throw new ArgumentException(nameof(exchangeHash));
            InitialIV = initialIV ?? throw new ArgumentException(nameof(initialIV));
            EncryptionKey = encryptionKey ?? throw new ArgumentException(nameof(encryptionKey));
            IntegrityKey = integrityKey ?? throw new ArgumentException(nameof(integrityKey));
        }

        public byte[] ExchangeHash { get; }
        public byte[] InitialIV { get; }
        public byte[] EncryptionKey { get; }
        public byte[] IntegrityKey { get; }
    }
}