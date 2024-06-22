// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Security.Cryptography;

namespace Tmds.Ssh;

public sealed class HostKey : IEquatable<HostKey>
{
    private string? _sha256FingerPrint;

    public string SHA256FingerPrint
    {
        get
        {
            if (_sha256FingerPrint == null)
            {
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(RawKey, hash);
                _sha256FingerPrint = Convert.ToBase64String(hash).TrimEnd('=');
            }
            return _sha256FingerPrint;
        }
    }

    internal HostKey(Name type, byte[] key)
    {
        if (type.IsEmpty)
        {
            throw new ArgumentException(nameof(type));
        }
        Type = type;
        RawKey = key ?? throw new ArgumentNullException(nameof(key));
    }

    internal Name Type { get; }

    internal byte[] RawKey { get; }

    public bool Equals(HostKey? other)
    {
        if (other is null)
        {
            return false;
        }

        return Type == other.Type && RawKey.AsSpan().SequenceEqual(other.RawKey);
    }
}
