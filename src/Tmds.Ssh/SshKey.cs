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
            Data = key ?? throw new ArgumentNullException(nameof(key));
        }

        public string Type { get; }

        public byte[] Data { get; }

        public override string ToString()
        {
            return $"{Type} {Convert.ToBase64String(Data)}";
        }

        public override int GetHashCode()
        {
            int hashCode = Type.GetHashCode();
            var span = Data.AsSpan();
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

            return Data.AsSpan().SequenceEqual(rhs.Data) && Type.Equals(rhs.Type);
        }
    }
}