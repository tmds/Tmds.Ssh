// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

public sealed class HostCertificateInfo
{
    public PublicKey IssuerKey { get; }

    internal HostCertificateInfo(
        PublicKey issuerKey,
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
