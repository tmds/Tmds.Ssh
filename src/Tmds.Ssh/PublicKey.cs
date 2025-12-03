// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

/// <summary>
/// Represents an SSH public key.
/// </summary>
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

    /// <summary>
    /// Gets the key type.
    /// </summary>
    public string Type => SshKeyData.Type.ToString();

    internal ReadOnlyMemory<byte> RawData => SshKeyData.RawData;

    /// <summary>
    /// Gets the SHA256 fingerprint of the key.
    /// </summary>
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

    /// <summary>
    /// Returns the key in OpenSSH string key format.
    /// </summary>
    /// <returns>String representation of the key.</returns>
    public override string ToString()
    {
        if (_toString is null)
        {
            // Format matches the known_hosts representation.
            _toString = $"{Type} {Convert.ToBase64String(RawData.Span)}";
        }
        return _toString;
    }

    /// <summary>
    /// Determines whether this key equals another.
    /// </summary>
    /// <param name="other">The key to compare.</param>
    /// <returns><see langword="true"/> if keys are equal.</returns>
    public bool Equals(PublicKey? other)
    {
        if (other is null)
        {
            return false;
        }

        return SshKeyData.Equals(other.RawData);
    }

    /// <summary>
    /// Returns the hash code for this key.
    /// </summary>
    /// <returns>Hash code.</returns>
    public override int GetHashCode()
    {
        return SshKeyData.GetHashCode();
    }
}
