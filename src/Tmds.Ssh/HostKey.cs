// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed partial class HostKey
{
    public string SHA256FingerPrint => ServerKey.SHA256FingerPrint;
    public string? IssuerSHA256FingerPrint => IssuerKey?.SHA256FingerPrint;

    internal SshKey ServerKey { get; }
    internal SshKey? IssuerKey => CertInfo?.IssuerKey;
    internal CertificateInfo? CertInfo { get; }

    internal SshKey ReceivedKey => CertInfo?.CertificateKey ?? ServerKey;

    internal PublicKey PublicKey { get; }

    internal HostKey(SshKey sshKey)
    {
        ArgumentNullException.ThrowIfNull(sshKey);

        if (sshKey.Type.EndsWith(AlgorithmNames.CertSuffix))
        {
            (PublicKey, CertInfo) = ParseCertificate(sshKey);
            ServerKey = CertInfo.SignedKey;
        }
        else
        {
            PublicKey = Ssh.PublicKey.CreateFromSshKey(sshKey);
            ServerKey = sshKey;
        }
    }
}
