// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

public sealed class HostKey : IEquatable<HostKey>
{
    internal SshKey SshKey { get; }
    private string? _sha256FingerPrint;

    public string SHA256FingerPrint
    {
        get
        {
            if (_sha256FingerPrint == null)
            {
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(SshKey.Data, hash);
                _sha256FingerPrint = Convert.ToBase64String(hash).TrimEnd('=');
            }
            return _sha256FingerPrint;
        }
    }

    internal HostKey(SshKey sshKey)
    {
        SshKey = sshKey ?? throw new ArgumentNullException(nameof(sshKey));
    }

    internal Name Type => SshKey.Type;

    public bool Equals(HostKey? other)
    {
        if (other is null)
        {
            return false;
        }

        return SshKey.Equals(other.SshKey);
    }

    public override int GetHashCode()
    {
        return SshKey.GetHashCode();
    }
}
