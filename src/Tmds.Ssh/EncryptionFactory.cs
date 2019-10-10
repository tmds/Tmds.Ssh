// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Tmds.Ssh
{
    sealed class EncryptionFactory
    {
        class EncryptionInfo
        {
            public EncryptionInfo(int keyLength, int ivLength, Func<Name, byte[], byte[], bool, IDisposableCryptoTransform> create)
            {
                KeyLength = keyLength;
                IVLength = ivLength;
                Create = create;
            }

            public int KeyLength { get; }
            public int IVLength { get; }
            public Func<Name, byte[], byte[], bool, IDisposableCryptoTransform> Create { get; }
        }

        private readonly Dictionary<Name, EncryptionInfo> _algorithms;

        public static EncryptionFactory Default = new EncryptionFactory();

        public EncryptionFactory()
        {
            _algorithms = new Dictionary<Name, EncryptionInfo>();
            _algorithms.Add(AlgorithmNames.Aes256Cbc, new EncryptionInfo(keyLength: 256 / 8, ivLength: 128 / 8, CreateAes));
        }

        public IDisposableCryptoTransform CreateDecryptor(Name name, byte[] key, byte[] iv)
        {
            // TODO check key.Length and iv.Length.
            return _algorithms[name].Create(name, key, iv, false);
        }

        public IDisposableCryptoTransform CreateEncryptor(Name name, byte[] key, byte[] iv)
        {
            // TODO check key.Length and iv.Length.
            return _algorithms[name].Create(name, key, iv, true);
        }

        public void GetKeyAndIVLength(Name name, out int keyLength, out int ivLength)
        {
            EncryptionInfo info = _algorithms[name];
            keyLength = info.KeyLength;
            ivLength = info.IVLength;
        }

        private static IDisposableCryptoTransform CreateAes(Name name, byte[] key, byte[] iv, bool encryptorNotDecryptor)
        {
            // TODO: switch (name)
            // case Aes256Cbc:
            var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;
            ICryptoTransform transform = encryptorNotDecryptor ? aes.CreateEncryptor() : aes.CreateDecryptor();
            return new EncryptionCryptoTransform(aes, transform, encryptorNotDecryptor);
        }
    }
}