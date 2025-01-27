// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

public sealed class PublicKey : IEquatable<PublicKey>
{
    internal SshKeyData SshKeyData { get; }
    private string? _sha256FingerPrint;
    private string? _toString;

    // For testing.
    internal PublicKey(string type, ReadOnlySpan<byte> rawData)
        : this(new SshKeyData(new Name(type), rawData.ToArray()))
    {  }

    internal PublicKey(SshKeyData sshKey)
    {
        if (sshKey.IsDefault)
        {
            throw new ArgumentException("Empty key");
        }
        SshKeyData = sshKey;
    }

    internal string Type => SshKeyData.Type.ToString();
    internal ReadOnlyMemory<byte> RawData => SshKeyData.RawData;

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
            // Format matches the known_hosts representation.
            _toString = $"{Type} {Convert.ToBase64String(RawData.Span)}";
        }
        return _toString;
    }

    public bool Equals(PublicKey? other)
    {
        if (other is null)
        {
            return false;
        }

        return SshKeyData.Equals(other.RawData);
    }

    public override int GetHashCode()
    {
        return SshKeyData.GetHashCode();
    }
}
