// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed partial class HostKey
{
    public string SHA256FingerPrint => PublicKey.SHA256FingerPrint;
    public string? IssuerSHA256FingerPrint => IssuerKey?.SHA256FingerPrint;

    internal SshKey RawKey { get; }

    internal SshKey PublicKey => CertInfo?.SignedKey ?? RawKey;
    internal SshKey? IssuerKey => CertInfo?.CAKey;
    internal SshKey? CertificateKey => IssuerKey is not null ? RawKey : null;

    internal PublicKey SignatureKey { get; }
    internal CertificateInfo? CertInfo { get; }

    internal HostKey(SshKey sshKey)
    {
        RawKey = sshKey ?? throw new ArgumentNullException(nameof(sshKey));

        if (sshKey.Type.EndsWith(AlgorithmNames.CertSuffix))
        {
            (SignatureKey, CertInfo) = ParseCertificate(sshKey);
        }
        else
        {
            SignatureKey = Ssh.PublicKey.CreateFromSshKey(sshKey);
        }
    }
}
