// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class CertificateCredential : Credential
{
    internal string Path { get; }
    internal PrivateKeyCredential PrivateKey { get; }

    public CertificateCredential(string path, PrivateKeyCredential privateKey)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(privateKey);

        Path = path;
        PrivateKey = privateKey;
    }
}
