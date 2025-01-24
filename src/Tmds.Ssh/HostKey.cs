// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed partial class HostKey
{
    public string SHA256FingerPrint => Key.SHA256FingerPrint;
    public string? IssuerSHA256FingerPrint => IssuerKey?.SHA256FingerPrint;

    // Public host key used by the server.
    internal SshKey Key { get; }
    // Public key used by the CA.
    internal SshKey? IssuerKey => CertInfo?.IssuerKey;
    internal CertificateInfo? CertInfo { get; }

    internal SshKey ReceivedKey => CertInfo?.CertificateKey ?? Key;

    internal PublicKey PublicKey { get; }

    internal HostKey(SshKey sshKey)
    {
        ArgumentNullException.ThrowIfNull(sshKey);

        if (sshKey.Type.EndsWith(AlgorithmNames.CertSuffix))
        {
            (PublicKey, CertInfo) = ParseCertificate(sshKey);
            Key = CertInfo.SignedKey;
        }
        else
        {
            PublicKey = Ssh.PublicKey.CreateFromSshKey(sshKey);
            Key = sshKey;
        }
    }
}
