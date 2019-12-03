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
            Type = type ?? throw new ArgumentNullException(nameof(type));
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public string Type { get; }

        public byte[] Key { get; }

        public override string ToString()
        {
            return $"{Type} {Convert.ToBase64String(Key)}";
        }

        public override int GetHashCode()
        {
            int hashCode = Type.GetHashCode();
            var span = Key.AsSpan();
            for (int i = 0; i < span.Length; i++)
            {
                hashCode = (hashCode << 8) ^ span[i];
            }
            return hashCode;
        }

        public override bool Equals(object obj)
        {
            SshKey? rhs = obj as SshKey;

            if (rhs == null)
            {
                return false;
            }

            return Key.AsSpan().SequenceEqual(rhs.Key) && Type.Equals(rhs.Type);
        }
    }
}