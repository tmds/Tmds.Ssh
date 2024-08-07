// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Collections.Immutable;

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

    // Host key algorithms.
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

    // Encryption algorithms.
    private static readonly byte[] Aes128GcmBytes = "aes128-gcm@openssh.com"u8.ToArray();
    public static Name Aes128Gcm => new Name(Aes128GcmBytes);
    private static readonly byte[] Aes256GcmBytes = "aes256-gcm@openssh.com"u8.ToArray();
    public static Name Aes256Gcm => new Name(Aes256GcmBytes);

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
    public static readonly Name[] SshRsaAlgorithms = [ RsaSshSha2_512, RsaSshSha2_256 ];

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

}
