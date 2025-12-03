// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Credential for certificate-based authentication.
/// </summary>
public sealed class CertificateCredential : Credential
{
    internal string Path { get; }
    internal PrivateKeyCredential PrivateKey { get; }

    /// <summary>
    /// Creates a credential for certificate-based authentication.
    /// </summary>
    /// <param name="path">Path to the certificate file.</param>
    /// <param name="privateKey"><see cref="PrivateKeyCredential"/> matching the certificate.</param>
    public CertificateCredential(string path, PrivateKeyCredential privateKey)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(privateKey);

        Path = path;
        PrivateKey = privateKey;
    }
}
