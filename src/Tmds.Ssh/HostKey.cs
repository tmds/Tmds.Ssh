// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed partial class HostKey
{
    // Public host key used by the server.
    public PublicKey Key { get; }
    public HostCertificateInfo? CertificateInfo { get; }

    [Obsolete($"Call {nameof(Key)}.{nameof(Key.SHA256FingerPrint)} instead.")]
    public string SHA256FingerPrint => Key.SHA256FingerPrint;

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
