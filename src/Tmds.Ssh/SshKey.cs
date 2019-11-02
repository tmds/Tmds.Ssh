// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Collections.Generic;

namespace Tmds.Ssh
{
    public sealed class SshKey
    {
        public SshKey(string type, byte[] key)
        {
            Type = type;
            Key = key;
        }

        public string Type { get; }

        public byte[] Key { get; }

        public override string ToString()
        {
            return $"{Type} {Convert.ToBase64String(Key)}";
        }
    }
}