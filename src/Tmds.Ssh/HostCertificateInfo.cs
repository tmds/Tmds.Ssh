// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

/// <summary>
/// Information about host certificate.
/// </summary>
public sealed class HostCertificateInfo
{
    /// <summary>
    /// Gets the certificate issuer's public key.
    /// </summary>
    public PublicKey IssuerKey { get; }

    /// <summary>
    /// Gets the certificate serial number.
    /// </summary>
    public ulong SerialNumber { get; }

    /// <summary>
    /// Gets the certificate identifier.
    /// </summary>
    public string Identifier { get; }

    /// <summary>
    /// Gets the certificate type.
    /// </summary>
    public string Type => CertificateKey.Type.ToString();

    internal HostCertificateInfo(
        PublicKey issuerKey,
        ulong serialNumber,
        string identifier,
        SshKeyData certificateKey,
        SshKeyData signedKey,
        bool hasCriticalOptions,
        DateTimeOffset validBefore,
        DateTimeOffset validAfter,
        List<string> principals,
        ReadOnlyMemory<byte> signedData,
        ReadOnlySequence<byte> signature,
        PublicKeyAlgorithm caPublicKey
    )
    {
        IssuerKey = issuerKey;
        SerialNumber = serialNumber;
        Identifier = identifier;
        CertificateKey = certificateKey;
        SignedKey = signedKey;
        HasCriticalOptions = hasCriticalOptions;
        ValidBefore = validBefore;
        ValidAfter = validAfter;
        Principals = principals;
        SignedData = signedData;
        Signature = signature;
        CAPublicKey = caPublicKey;
    }

    internal SshKeyData CertificateKey { get; }
    internal SshKeyData SignedKey { get; }

    internal bool HasCriticalOptions { get; }
    internal DateTimeOffset ValidBefore { get; }
    internal DateTimeOffset ValidAfter { get; }
    internal List<string> Principals { get; }

    internal ReadOnlyMemory<byte> SignedData { get; }
    internal ReadOnlySequence<byte> Signature { get; }
    internal PublicKeyAlgorithm CAPublicKey { get; }
#if DEBUG
    internal bool IsVerified;
#endif
}
