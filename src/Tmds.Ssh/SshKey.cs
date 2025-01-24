// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class SshKey : IEquatable<SshKey>
{
    private string? _sha256FingerPrint;
    private string? _toString;

    internal SshKey(Name type, byte[] data)
    {
        if (type.IsEmpty)
        {
            throw new ArgumentException(nameof(type));
        }
        Type = type;
        RawData = data ?? throw new ArgumentNullException(nameof(data));
    }

    internal Name Type { get; }

    internal ReadOnlyMemory<byte> RawData { get; }

    public bool Equals(SshKey? other)
    {
        if (other is null)
        {
            return false;
        }

        return RawData.Span.SequenceEqual(other.RawData.Span);
    }

    public override int GetHashCode()
    {
        HashCode hashCode = new HashCode();
        hashCode.AddBytes(RawData.Span);
        return hashCode.ToHashCode();
    }

    public string SHA256FingerPrint
    {
        get
        {
            if (_sha256FingerPrint is null)
            {
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(RawData.Span, hash);
                _sha256FingerPrint = Convert.ToBase64String(hash).TrimEnd('=');
            }
            return _sha256FingerPrint;
        }
    }

    public override string ToString()
    {
        if (_toString is null)
        {
            _toString = $"{Type} {Convert.ToBase64String(RawData.Span)}";
        }
        return _toString;
    }
}
