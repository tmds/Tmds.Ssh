// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class SshKey : IEquatable<SshKey>
{
    private string? _sha256FingerPrint;

    public SshKey(Name type, byte[] data)
    {
        if (type.IsEmpty)
        {
            throw new ArgumentException(nameof(type));
        }
        Type = type;
        Data = data ?? throw new ArgumentNullException(nameof(data));
    }

    public Name Type { get; }

    public byte[] Data { get; }

    public bool Equals(SshKey? other)
    {
        if (other is null)
        {
            return false;
        }

        return Data.AsSpan().SequenceEqual(other.Data);
    }

    public override int GetHashCode()
    {
        HashCode hashCode = new HashCode();
        hashCode.AddBytes(Data.AsSpan());
        return hashCode.ToHashCode();
    }

    internal string SHA256FingerPrint
    {
        get
        {
            if (_sha256FingerPrint is null)
            {
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(Data, hash);
                _sha256FingerPrint = Convert.ToBase64String(hash).TrimEnd('=');
            }
            return _sha256FingerPrint;
        }
    }
}
