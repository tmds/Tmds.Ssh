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

    // Encryption algorithms.
    private static readonly byte[] Aes128GcmBytes = "aes128-gcm@openssh.com"u8.ToArray();
    public static Name Aes128Gcm => new Name(Aes128GcmBytes);
    private static readonly byte[] Aes256GcmBytes = "aes256-gcm@openssh.com"u8.ToArray();
    public static Name Aes256Gcm => new Name(Aes256GcmBytes);

    // Mac algorithms.
    private static readonly byte[] HMacSha2_256Bytes = "hmac-sha2-256"u8.ToArray();
    public static Name HMacSha2_256 => new Name(HMacSha2_256Bytes);

    // Curve names.
    private static readonly byte[] Nistp265Bytes = "nistp256"u8.ToArray();
    public static Name Nistp265 => new Name(Nistp265Bytes);

    // These fields are initialized in order, so these list must be created after the names.
    // Algorithms are in **order of preference**.
    public static readonly ImmutableArray<Name> SshRsaAlgorithms =
        ImmutableArray.Create([RsaSshSha2_512, RsaSshSha2_256]);
}
