// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;

namespace Tmds.Ssh;

static class AlgorithmNames
{
    public const string CertSuffix = "-cert-v01@openssh.com";

    public static Name None => Name.FromKnownNameString(KnownNameStrings.None);

    // Key exchange algorithms
    public static Name EcdhSha2Nistp256 => Name.FromKnownNameString(KnownNameStrings.EcdhSha2Nistp256);
    public static Name EcdhSha2Nistp384 => Name.FromKnownNameString(KnownNameStrings.EcdhSha2Nistp384);
    public static Name EcdhSha2Nistp521 => Name.FromKnownNameString(KnownNameStrings.EcdhSha2Nistp521);
    public static Name Curve25519Sha256 => Name.FromKnownNameString(KnownNameStrings.Curve25519Sha256);
    public static Name Curve25519Sha256LibSsh => Name.FromKnownNameString(KnownNameStrings.Curve25519Sha256LibSsh);
    public static Name SNtruP761X25519Sha512 => Name.FromKnownNameString(KnownNameStrings.SNtruP761X25519Sha512);
    public static Name SNtruP761X25519Sha512OpenSsh => Name.FromKnownNameString(KnownNameStrings.SNtruP761X25519Sha512OpenSsh);
    public static Name MLKem768X25519Sha256 => Name.FromKnownNameString(KnownNameStrings.MLKem768X25519Sha256);
    // Host key types
    public static Name SshRsa => Name.FromKnownNameString(KnownNameStrings.SshRsa);
    public static Name SshRsaCert => Name.FromKnownNameString(KnownNameStrings.SshRsaCert);
    // Host key algorithms
    public static Name RsaSshSha2_256 => Name.FromKnownNameString(KnownNameStrings.RsaSshSha2_256);
    public static Name RsaSshSha2_512 => Name.FromKnownNameString(KnownNameStrings.RsaSshSha2_512);
    public static Name RsaSshSha2_256Cert => Name.FromKnownNameString(KnownNameStrings.RsaSshSha2_256Cert);
    public static Name RsaSshSha2_512Cert => Name.FromKnownNameString(KnownNameStrings.RsaSshSha2_512Cert);
    // Host key algorithms and host key types
    public static Name EcdsaSha2Nistp256 => Name.FromKnownNameString(KnownNameStrings.EcdsaSha2Nistp256);
    public static Name EcdsaSha2Nistp384 => Name.FromKnownNameString(KnownNameStrings.EcdsaSha2Nistp384);
    public static Name EcdsaSha2Nistp521 => Name.FromKnownNameString(KnownNameStrings.EcdsaSha2Nistp521);
    public static Name SshEd25519 => Name.FromKnownNameString(KnownNameStrings.SshEd25519);
    public static Name EcdsaSha2Nistp256Cert => Name.FromKnownNameString(KnownNameStrings.EcdsaSha2Nistp256Cert);
    public static Name EcdsaSha2Nistp384Cert => Name.FromKnownNameString(KnownNameStrings.EcdsaSha2Nistp384Cert);
    public static Name EcdsaSha2Nistp521Cert => Name.FromKnownNameString(KnownNameStrings.EcdsaSha2Nistp521Cert);
    public static Name SshEd25519Cert => Name.FromKnownNameString(KnownNameStrings.SshEd25519Cert);
    // Encryption algorithms
    public static Name Aes128Cbc => Name.FromKnownNameString(KnownNameStrings.Aes128Cbc);
    public static Name Aes192Cbc => Name.FromKnownNameString(KnownNameStrings.Aes192Cbc);
    public static Name Aes256Cbc => Name.FromKnownNameString(KnownNameStrings.Aes256Cbc);
    public static Name Aes128Ctr => Name.FromKnownNameString(KnownNameStrings.Aes128Ctr);
    public static Name Aes192Ctr => Name.FromKnownNameString(KnownNameStrings.Aes192Ctr);
    public static Name Aes256Ctr => Name.FromKnownNameString(KnownNameStrings.Aes256Ctr);
    public static Name Aes128Gcm => Name.FromKnownNameString(KnownNameStrings.Aes128Gcm);
    public static Name Aes256Gcm => Name.FromKnownNameString(KnownNameStrings.Aes256Gcm);
    public static Name ChaCha20Poly1305 => Name.FromKnownNameString(KnownNameStrings.ChaCha20Poly1305);
    // KDF algorithms
    public static Name BCrypt => Name.FromKnownNameString(KnownNameStrings.BCrypt);
    // MAC Algorithms
    public static Name HMacSha2_256 => Name.FromKnownNameString(KnownNameStrings.HMacSha2_256);
    // Curve names
    public static Name Nistp256 => Name.FromKnownNameString(KnownNameStrings.Nistp256);
    public static Name Nistp384 => Name.FromKnownNameString(KnownNameStrings.Nistp384);
    public static Name Nistp521 => Name.FromKnownNameString(KnownNameStrings.Nistp521);
    // Authentications
    public static Name GssApiWithMic => Name.FromKnownNameString(KnownNameStrings.GssApiWithMic);
    public static Name HostBased => Name.FromKnownNameString(KnownNameStrings.HostBased);
    public static Name KeyboardInteractive => Name.FromKnownNameString(KnownNameStrings.KeyboardInteractive);
    public static Name Password => Name.FromKnownNameString(KnownNameStrings.Password);
    public static Name PublicKey => Name.FromKnownNameString(KnownNameStrings.PublicKey);
    // Strict key exchange
    public static Name ClientStrictKex => Name.FromKnownNameString(KnownNameStrings.ClientStrictKex);
    public static Name ServerStrictKex => Name.FromKnownNameString(KnownNameStrings.ServerStrictKex);
    // Extension Negotiation
    public static Name ClientExtensionNegotiation => Name.FromKnownNameString(KnownNameStrings.ClientExtensionNegotiation);
    // Channel types
    public static Name ForwardTcpIp => Name.FromKnownNameString(KnownNameStrings.ForwardTcpIp);

    // For GetSignatureAlgorithmsForKeyType
    internal static readonly Name[] SshRsaAlgorithms = [ RsaSshSha2_512, RsaSshSha2_256 ];
    internal static readonly Name[] SshRsaCertAlgorithms = [ RsaSshSha2_512Cert, RsaSshSha2_256Cert ];
    internal static readonly Name[] EcdsaSha2Nistp256Algorithms = [ EcdsaSha2Nistp256 ];
    internal static readonly Name[] EcdsaSha2Nistp384Algorithms = [ EcdsaSha2Nistp384 ];
    internal static readonly Name[] EcdsaSha2Nistp521Algorithms = [ EcdsaSha2Nistp521 ];
    internal static readonly Name[] SshEd25519Algorithms = [ SshEd25519 ];

    // Returns the signature algorithms supported by the public key.
    // Note: not implemented for certificate key types. The caller needs to pass in the public key that is signed by the certificate.
    public static Name[] GetSignatureAlgorithmsForKeyType(Name keyType)
    {
        // This method doesn't map cert host key types to signature algorithms.
        Debug.Assert(!keyType.EndsWith(CertSuffix));

        if (keyType == SshRsa)
        {
            return SshRsaAlgorithms;
        }
        else if (keyType == EcdsaSha2Nistp256)
        {
            return EcdsaSha2Nistp256Algorithms;
        }
        else if (keyType == EcdsaSha2Nistp384)
        {
            return EcdsaSha2Nistp384Algorithms;
        }
        else if (keyType == EcdsaSha2Nistp521)
        {
            return EcdsaSha2Nistp521Algorithms;
        }
        else if (keyType == SshEd25519)
        {
            return SshEd25519Algorithms;
        }
        else
        {
            Debug.Assert(false);
            // Assume an unknown key type (e.g. from SSH Agent) matches with the signature algorithm it provides.
            return [ keyType ];
        }
    }

    // Returns the host key algorithms that this host key supports.
    public static ReadOnlySpan<Name> GetHostKeyAlgorithmsForHostKeyType(ref Name hostKeyType)
    {
        if (hostKeyType == SshRsa)
        {
            return SshRsaAlgorithms;
        }
        else if (hostKeyType == SshRsaCert)
        {
            return SshRsaCertAlgorithms;
        }
        else
        {
            return new ReadOnlySpan<Name>(ref hostKeyType);
        }
    }

    // For GetHostKeyAlgorithmsForKnownHostKeyType
    internal static readonly Name[] SshRsaKnownHostAlgorithms = [ RsaSshSha2_512Cert, RsaSshSha2_256Cert, RsaSshSha2_512, RsaSshSha2_256 ];
    internal static readonly Name[] EcdsaSha2Nistp256KnownHostAlgorithms = [ EcdsaSha2Nistp256Cert, EcdsaSha2Nistp256 ];
    internal static readonly Name[] EcdsaSha2Nistp384KnownHostAlgorithms = [ EcdsaSha2Nistp384Cert, EcdsaSha2Nistp384 ];
    internal static readonly Name[] EcdsaSha2Nistp521KnownHostAlgorithms = [ EcdsaSha2Nistp521Cert, EcdsaSha2Nistp521 ];
    internal static readonly Name[] SshEd25519KnownHostAlgorithms = [ SshEd25519Cert, SshEd25519 ];

    // Returns the host key algorithms that this known_hosts key can be checked against.
    // The returned value includes certificate host algorithms compatible with the host key.
    public static ReadOnlySpan<Name> GetHostKeyAlgorithmsForKnownHostKeyType(ref Name knownHostKeyType)
    {
        if (knownHostKeyType == SshRsa)
        {
            return SshRsaKnownHostAlgorithms;
        }
        if (knownHostKeyType == EcdsaSha2Nistp256)
        {
            return EcdsaSha2Nistp256KnownHostAlgorithms;
        }
        if (knownHostKeyType == EcdsaSha2Nistp384)
        {
            return EcdsaSha2Nistp384KnownHostAlgorithms;
        }
        if (knownHostKeyType == EcdsaSha2Nistp521)
        {
            return EcdsaSha2Nistp521KnownHostAlgorithms;
        }
        if (knownHostKeyType == SshEd25519)
        {
            return SshEd25519KnownHostAlgorithms;
        }
        else
        {
            return new ReadOnlySpan<Name>(ref knownHostKeyType);
        }
    }

    // Returns the host key algorithm name for using the specified signature with the specified host key type.
    public static Name GetHostKeyAlgorithmForSignatureAlgorithm(Name hostKeyType, Name signatureType)
    {
        if (hostKeyType == SshRsa)
        {
            return signatureType;
        }
        else if (hostKeyType == SshRsaCert)
        {
            if (signatureType == RsaSshSha2_256)
            {
                return RsaSshSha2_256Cert;
            }
            else if (signatureType == RsaSshSha2_512)
            {
                return RsaSshSha2_512Cert;
            }
        }
        return hostKeyType;
    }
}
