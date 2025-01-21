// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed partial class HostKey : IEquatable<HostKey>
{
    private string? _sha256FingerPrint;
    private string? _issuerSha256FingerPrint;

    public string SHA256FingerPrint
        => _sha256FingerPrint ??= SshKey.GetSHA256FingerPrint();

    public string? IssuerSHA256FingerPrint
        => _issuerSha256FingerPrint ??= CertInfo?.CAKey?.GetSHA256FingerPrint();

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

    internal SshKey SshKey { get; }
    internal PublicKey PublicKey { get; }
    internal Name Type => SshKey.Type;
    internal CertificateInfo? CertInfo { get; }

    internal HostKey(SshKey sshKey, bool parseKey = true)
    {
        SshKey = sshKey ?? throw new ArgumentNullException(nameof(sshKey));

        if (parseKey)
        {
            if (sshKey.Type.AsSpan().EndsWith(AlgorithmNames.CertSuffix))
            {
                (PublicKey, CertInfo) = ParseCertificate(sshKey);
            }
            else
            {
                PublicKey = Ssh.PublicKey.CreateFromSshKey(sshKey);
            }
        }
        else
        {
            PublicKey = null!;
        }
    }
}
