// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Text;

namespace Tmds.Ssh.Managed
{
    // Internal names used to identify algorithms or protocols are normally
    // never displayed to users, and must be in US-ASCII.
    readonly struct Name : IEquatable<Name>
    {
        // By design, we treat _name == null the same as _name == byte[0] {}.
        private readonly byte[] _name;

        private Name(byte[] name)
        {
            _name = name;
        }

        internal Name(string name)
        {
            _name = Encoding.ASCII.GetBytes(name);
        }

        public static bool TryCreate(byte[] bytes, out Name name)
        {
            if (bytes == null)
            {
                ThrowHelper.ThrowArgumentNull(nameof(name));
            }

            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];
                if (b < 32 || b > 126)
                {
                    ThrowHelper.ThrowProtocolInvalidAscii();
                }
            }
            name = new Name(bytes);
            return true;
        }

        public override string ToString()
        {
            return _name == null ? string.Empty : Encoding.ASCII.GetString(_name);
        }

        public override int GetHashCode()
        {
            var span = _name.AsSpan();
            int hashCode = span.Length == 0 ? 0 : 0x38723781;
            for (int i = 0; i < span.Length; i++)
            {
                hashCode = (hashCode << 8) ^ span[i];
            }
            return hashCode;
        }

        public bool Equals(Name other)
        {
            return _name.AsSpan().SequenceEqual(other._name.AsSpan());
        }

        public override bool Equals(object? obj)
        {
            return obj is Name name && Equals(name);
        }

        public static bool operator ==(Name left, Name right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(Name left, Name right)
        {
            return !(left == right);
        }

        public ReadOnlySpan<byte> AsSpan() => _name;

        public bool IsEmpty => _name == null || _name.Length == 0;
    }
}