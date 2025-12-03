// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Represents a host key.
/// </summary>
public sealed partial class HostKey
{
    /// <summary>
    /// Gets the public key.
    /// </summary>
    public PublicKey Key { get; }

    /// <summary>
    /// Gets the certificate information if the host key is stored in a certificate.
    /// </summary>
    public HostCertificateInfo? CertificateInfo { get; }

    internal Name ReceivedKeyType { get; }
    internal PublicKeyAlgorithm PublicKey { get; }

    internal HostKey(SshKeyData sshKey)
    {
        ReceivedKeyType = sshKey.Type;

        if (sshKey.Type.EndsWith(AlgorithmNames.CertSuffix))
        {
            (PublicKey, CertificateInfo) = ParseCertificate(sshKey);
            Key = new PublicKey(CertificateInfo.SignedKey);
        }
        else
        {
            PublicKey = PublicKeyAlgorithm.CreateFromSshKey(sshKey);
            Key = new PublicKey(sshKey);
        }
    }
}
