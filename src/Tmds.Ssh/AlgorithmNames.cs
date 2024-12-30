// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

static class AlgorithmNames // TODO: rename to KnownNames
{
    // MAYDO: put these names in byte[] arrays.

    private static readonly byte[] NoneBytes = "none"u8.ToArray();
    public static Name None => new Name(NoneBytes);

    // Key exchange algorithms
    private static readonly byte[] EcdhSha2Nistp256Bytes = "ecdh-sha2-nistp256"u8.ToArray();
    public static Name EcdhSha2Nistp256 => new Name(EcdhSha2Nistp256Bytes);
    private static readonly byte[] EcdhSha2Nistp384Bytes = "ecdh-sha2-nistp384"u8.ToArray();
    public static Name EcdhSha2Nistp384 => new Name(EcdhSha2Nistp384Bytes);
    private static readonly byte[] EcdhSha2Nistp521Bytes = "ecdh-sha2-nistp521"u8.ToArray();
    public static Name EcdhSha2Nistp521 => new Name(EcdhSha2Nistp521Bytes);
    private static readonly byte[] Curve25519Sha256Bytes = "curve25519-sha256"u8.ToArray();
    public static Name Curve25519Sha256 => new Name(Curve25519Sha256Bytes);
    private static readonly byte[] Curve25519Sha256LibSshBytes = "curve25519-sha256@libssh.org"u8.ToArray();
    public static Name Curve25519Sha256LibSsh => new Name(Curve25519Sha256LibSshBytes);
    private static readonly byte[] SNtruP761X25519Sha512Bytes = "sntrup761x25519-sha512"u8.ToArray();
    public static Name SNtruP761X25519Sha512 => new Name(SNtruP761X25519Sha512Bytes);
    private static readonly byte[] SNtruP761X25519Sha512OpenSshBytes = "sntrup761x25519-sha512@openssh.com"u8.ToArray();
    public static Name SNtruP761X25519Sha512OpenSsh => new Name(SNtruP761X25519Sha512OpenSshBytes);

    // Host key algorithms: key types and signature algorithms.
    private static readonly byte[] SshRsaBytes = "ssh-rsa"u8.ToArray();
    public static Name SshRsa => new Name(SshRsaBytes);
    private static readonly byte[] RsaSshSha2_256Bytes = "rsa-sha2-256"u8.ToArray();
    public static Name RsaSshSha2_256 => new Name(RsaSshSha2_256Bytes);
    private static readonly byte[] RsaSshSha2_512Bytes = "rsa-sha2-512"u8.ToArray();
    public static Name RsaSshSha2_512 => new Name(RsaSshSha2_512Bytes);
    private static readonly byte[] EcdsaSha2Nistp256Bytes = "ecdsa-sha2-nistp256"u8.ToArray();
    public static Name EcdsaSha2Nistp256 => new Name(EcdsaSha2Nistp256Bytes);
    private static readonly byte[] EcdsaSha2Nistp384Bytes = "ecdsa-sha2-nistp384"u8.ToArray();
    public static Name EcdsaSha2Nistp384 => new Name(EcdsaSha2Nistp384Bytes);
    private static readonly byte[] EcdsaSha2Nistp521Bytes = "ecdsa-sha2-nistp521"u8.ToArray();
    public static Name EcdsaSha2Nistp521 => new Name(EcdsaSha2Nistp521Bytes);
    private static readonly byte[] SshEd25519Bytes = "ssh-ed25519"u8.ToArray();
    public static Name SshEd25519 => new Name(SshEd25519Bytes);
    // Key type to signature algorithms.
    public static readonly Name[] SshRsaAlgorithms = [ RsaSshSha2_512, RsaSshSha2_256 ];
    public static readonly Name[] EcdsaSha2Nistp256Algorithms = [ EcdsaSha2Nistp256 ];
    public static readonly Name[] EcdsaSha2Nistp384Algorithms = [ EcdsaSha2Nistp384 ];
    public static readonly Name[] EcdsaSha2Nistp521Algorithms = [ EcdsaSha2Nistp521 ];
    public static readonly Name[] SshEd25519Algorithms = [ SshEd25519 ];

    public static Name[] GetAlgorithmsForKeyType(Name keyType)
    {
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
            // Unknown key types.
            return [ keyType ];
        }
    }

    // Encryption algorithms.
    private static readonly byte[] Aes128CbcBytes = "aes128-cbc"u8.ToArray();
    public static Name Aes128Cbc => new Name(Aes128CbcBytes);
    private static readonly byte[] Aes192CbcBytes = "aes192-cbc"u8.ToArray();
    public static Name Aes192Cbc => new Name(Aes192CbcBytes);
    private static readonly byte[] Aes256CbcBytes = "aes256-cbc"u8.ToArray();
    public static Name Aes256Cbc => new Name(Aes256CbcBytes);
    private static readonly byte[] Aes128CtrBytes = "aes128-ctr"u8.ToArray();
    public static Name Aes128Ctr => new Name(Aes128CtrBytes);
    private static readonly byte[] Aes192CtrBytes = "aes192-ctr"u8.ToArray();
    public static Name Aes192Ctr => new Name(Aes192CtrBytes);
    private static readonly byte[] Aes256CtrBytes = "aes256-ctr"u8.ToArray();
    public static Name Aes256Ctr => new Name(Aes256CtrBytes);
    private static readonly byte[] Aes128GcmBytes = "aes128-gcm@openssh.com"u8.ToArray();
    public static Name Aes128Gcm => new Name(Aes128GcmBytes);
    private static readonly byte[] Aes256GcmBytes = "aes256-gcm@openssh.com"u8.ToArray();
    public static Name Aes256Gcm => new Name(Aes256GcmBytes);
    private static readonly byte[] ChaCha20Poly1305Bytes = "chacha20-poly1305@openssh.com"u8.ToArray();
    public static Name ChaCha20Poly1305 => new Name(ChaCha20Poly1305Bytes);

    // KDF algorithms:
    private static readonly byte[] BCryptBytes = "bcrypt"u8.ToArray();
    public static Name BCrypt => new Name(BCryptBytes);

    // Mac algorithms.
    private static readonly byte[] HMacSha2_256Bytes = "hmac-sha2-256"u8.ToArray();
    public static Name HMacSha2_256 => new Name(HMacSha2_256Bytes);

    // Curve names.
    private static readonly byte[] Nistp256Bytes = "nistp256"u8.ToArray();
    public static Name Nistp256 => new Name(Nistp256Bytes);
    private static readonly byte[] Nistp384Bytes = "nistp384"u8.ToArray();
    public static Name Nistp384 => new Name(Nistp384Bytes);
    private static readonly byte[] Nistp521Bytes = "nistp521"u8.ToArray();
    public static Name Nistp521 => new Name(Nistp521Bytes);

    // These fields are initialized in order, so these list must be created after the names.
    // Algorithms are in **order of preference**.

    // Authentications
    private static readonly byte[] GssApiWithMicBytes = "gssapi-with-mic"u8.ToArray();
    public static Name GssApiWithMic => new Name(GssApiWithMicBytes);
    private static readonly byte[] HostBasedBytes = "hostbased"u8.ToArray();
    public static Name HostBased => new Name(HostBasedBytes);
    private static readonly byte[] KeyboardInteractiveBytes = "keyboard-interactive"u8.ToArray();
    public static Name KeyboardInteractive => new Name(KeyboardInteractiveBytes);
    private static readonly byte[] PasswordBytes = "password"u8.ToArray();
    public static Name Password => new Name(PasswordBytes);
    private static readonly byte[] PublicKeyBytes = "publickey"u8.ToArray();
    public static Name PublicKey => new Name(PublicKeyBytes);

    // Strict key exchange
    private static readonly byte[] ClientStrictKexBytes = "kex-strict-c-v00@openssh.com"u8.ToArray();
    public static Name ClientStrictKex => new Name(ClientStrictKexBytes);
    private static readonly byte[] PServerStrictKexBytes = "kex-strict-s-v00@openssh.com"u8.ToArray();
    public static Name ServerStrictKex => new Name(PServerStrictKexBytes);
}
