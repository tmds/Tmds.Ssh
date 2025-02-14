// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

static class KnownNameStrings
{
    internal const string None = "none";
    internal const string EcdhSha2Nistp256 = "ecdh-sha2-nistp256";
    internal const string EcdhSha2Nistp384 = "ecdh-sha2-nistp384";
    internal const string EcdhSha2Nistp521 = "ecdh-sha2-nistp521";
    internal const string Curve25519Sha256 = "curve25519-sha256";
    internal const string Curve25519Sha256LibSsh = "curve25519-sha256@libssh.org";
    internal const string SNtruP761X25519Sha512 = "sntrup761x25519-sha512";
    internal const string SNtruP761X25519Sha512OpenSsh = "sntrup761x25519-sha512@openssh.com";
    internal const string MLKem768X25519Sha256 = "mlkem768x25519-sha256";
    internal const string SshRsa = "ssh-rsa";
    internal const string RsaSshSha2_256 = "rsa-sha2-256";
    internal const string RsaSshSha2_512 = "rsa-sha2-512";
    internal const string EcdsaSha2Nistp256 = "ecdsa-sha2-nistp256";
    internal const string EcdsaSha2Nistp384 = "ecdsa-sha2-nistp384";
    internal const string EcdsaSha2Nistp521 = "ecdsa-sha2-nistp521";
    internal const string SshEd25519 = "ssh-ed25519";
    internal const string SshRsaCert = "ssh-rsa-cert-v01@openssh.com";
    internal const string RsaSshSha2_256Cert = "rsa-sha2-256-cert-v01@openssh.com";
    internal const string RsaSshSha2_512Cert = "rsa-sha2-512-cert-v01@openssh.com";
    internal const string EcdsaSha2Nistp256Cert = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
    internal const string EcdsaSha2Nistp384Cert = "ecdsa-sha2-nistp384-cert-v01@openssh.com";
    internal const string EcdsaSha2Nistp521Cert = "ecdsa-sha2-nistp521-cert-v01@openssh.com";
    internal const string SshEd25519Cert = "ssh-ed25519-cert-v01@openssh.com";
    internal const string Aes128Cbc = "aes128-cbc";
    internal const string Aes192Cbc = "aes192-cbc";
    internal const string Aes256Cbc = "aes256-cbc";
    internal const string Aes128Ctr = "aes128-ctr";
    internal const string Aes192Ctr = "aes192-ctr";
    internal const string Aes256Ctr = "aes256-ctr";
    internal const string Aes128Gcm = "aes128-gcm@openssh.com";
    internal const string Aes256Gcm = "aes256-gcm@openssh.com";
    internal const string ChaCha20Poly1305 = "chacha20-poly1305@openssh.com";
    internal const string BCrypt = "bcrypt";
    internal const string HMacSha2_256 = "hmac-sha2-256";
    internal const string Nistp256 = "nistp256";
    internal const string Nistp384 = "nistp384";
    internal const string Nistp521 = "nistp521";
    internal const string GssApiWithMic = "gssapi-with-mic";
    internal const string HostBased = "hostbased";
    internal const string KeyboardInteractive = "keyboard-interactive";
    internal const string Password = "password";
    internal const string PublicKey = "publickey";
    internal const string ClientStrictKex = "kex-strict-c-v00@openssh.com";
    internal const string ServerStrictKex = "kex-strict-s-v00@openssh.com";
    internal const string ClientExtensionNegotiation = "ext-info-c";
    internal const string ForwardTcpIp = "forwarded-tcpip";

    public static string? FindKnownName(ReadOnlySpan<char> name)
    {
        // This maps the argument to the string with the same value.
        // The result may then be compared through reference equality rather than comparing the string value.
        // The compiler will optimize the switch statement below for an efficient lookup against the const strings.
        switch(name)
        {
            case None: return None;
            case EcdhSha2Nistp256: return EcdhSha2Nistp256;
            case EcdhSha2Nistp384: return EcdhSha2Nistp384;
            case EcdhSha2Nistp521: return EcdhSha2Nistp521;
            case Curve25519Sha256: return Curve25519Sha256;
            case Curve25519Sha256LibSsh: return Curve25519Sha256LibSsh;
            case SNtruP761X25519Sha512: return SNtruP761X25519Sha512;
            case SNtruP761X25519Sha512OpenSsh: return SNtruP761X25519Sha512OpenSsh;
            case MLKem768X25519Sha256: return MLKem768X25519Sha256;
            case SshRsa: return SshRsa;
            case RsaSshSha2_256: return RsaSshSha2_256;
            case RsaSshSha2_512: return RsaSshSha2_512;
            case EcdsaSha2Nistp256: return EcdsaSha2Nistp256;
            case EcdsaSha2Nistp384: return EcdsaSha2Nistp384;
            case EcdsaSha2Nistp521: return EcdsaSha2Nistp521;
            case SshEd25519: return SshEd25519;
            case SshRsaCert: return SshRsaCert;
            case RsaSshSha2_256Cert: return RsaSshSha2_256Cert;
            case RsaSshSha2_512Cert: return RsaSshSha2_512Cert;
            case EcdsaSha2Nistp256Cert: return EcdsaSha2Nistp256Cert;
            case EcdsaSha2Nistp384Cert: return EcdsaSha2Nistp384Cert;
            case EcdsaSha2Nistp521Cert: return EcdsaSha2Nistp521Cert;
            case SshEd25519Cert: return SshEd25519Cert;
            case Aes128Cbc: return Aes128Cbc;
            case Aes192Cbc: return Aes192Cbc;
            case Aes256Cbc: return Aes256Cbc;
            case Aes128Ctr: return Aes128Ctr;
            case Aes192Ctr: return Aes192Ctr;
            case Aes256Ctr: return Aes256Ctr;
            case Aes128Gcm: return Aes128Gcm;
            case Aes256Gcm: return Aes256Gcm;
            case ChaCha20Poly1305: return ChaCha20Poly1305;
            case BCrypt: return BCrypt;
            case HMacSha2_256: return HMacSha2_256;
            case Nistp256: return Nistp256;
            case Nistp384: return Nistp384;
            case Nistp521: return Nistp521;
            case GssApiWithMic: return GssApiWithMic;
            case HostBased: return HostBased;
            case KeyboardInteractive: return KeyboardInteractive;
            case Password: return Password;
            case PublicKey: return PublicKey;
            case ClientStrictKex: return ClientStrictKex;
            case ServerStrictKex: return ServerStrictKex;
            case ClientExtensionNegotiation: return ClientExtensionNegotiation;
            case ForwardTcpIp: return ForwardTcpIp;
            default: return null;
        }
    }
}
