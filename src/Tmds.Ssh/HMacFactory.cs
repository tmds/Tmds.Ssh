// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Tmds.Ssh
{
    sealed class HMacFactory
    {
        class HashInfo
        {
            public HashInfo(int keyLength, Func<Name, byte[], IHMac> create)
            {
                KeyLength = keyLength;
                Create = create;
            }

            public int KeyLength { get; }
            public Func<Name, byte[], IHMac> Create { get; }
        }

        private readonly Dictionary<Name, HashInfo> _algorithms;

        public static HMacFactory Default = new HMacFactory();

        public HMacFactory()
        {
            _algorithms = new Dictionary<Name, HashInfo>
            {
                { AlgorithmNames.HMacSha2_256, new HashInfo(256 / 8, (name, key) => new HMac(HashAlgorithmName.SHA256, 256 / 8, 256 / 8, key)) }
            };
        }

        public IHMac Create(Name name, byte[] key)
        {
            HashInfo info = _algorithms[name];
            if (info.KeyLength != key.Length)
            {
                throw new ArgumentException(nameof(key));
            }
            return info.Create(name, key);
        }

        public int GetKeyLength(Name name)
        {
            return _algorithms[name].KeyLength;
        }
    }
}