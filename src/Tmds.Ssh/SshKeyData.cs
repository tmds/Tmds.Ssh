// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

readonly struct SshKeyData : IEquatable<SshKeyData>
{
    private readonly byte[] _data;

    internal SshKeyData(Name type, byte[] data)
    {
        if (type.IsEmpty)
        {
            throw new ArgumentException(nameof(type));
        }
        if (data.Length == 0)
        {
            throw new ArgumentException(nameof(data));
        }
        Type = type;
        _data = data ?? throw new ArgumentNullException(nameof(data));
    }

    internal Name Type { get; }
    public ReadOnlyMemory<byte> RawData => _data;

    public bool Equals(SshKeyData other)
    {
        return Type == other.Type && _data.SequenceEqual(other._data);
    }

    public override int GetHashCode()
    {
        HashCode hashCode = new HashCode();
        hashCode.AddBytes(_data);
        return hashCode.ToHashCode();
    }

    public bool IsDefault => _data is null;
}
