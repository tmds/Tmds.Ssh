// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

sealed class SshKey : IEquatable<SshKey>
{
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
}
