// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh.Managed
{
    static class AlgorithmNames // TODO: rename to KnownNames
    {
        // MAYDO: put these names in byte[] arrays.

        public static Name None => new Name("none");

        // Key exchange algorithms
        public static Name EcdhSha2Nistp256 => new Name("ecdh-sha2-nistp256");

        // Host key algorithms.
        public static Name SshRsa => new Name("ssh-rsa");
        public static Name SshSha2_256 => new Name("rsa-sha2-256");
        public static Name EcdsaSha2Nistp256 => new Name("ecdsa-sha2-nistp256");

        // Encryption algorithms.
        public static Name Aes256Cbc => new Name("aes256-cbc");
        public static Name Aes128Gcm => new Name("aes128-gcm@openssh.com");

        // Mac algorithms.
        public static Name HMacSha2_256 => new Name("hmac-sha2-256");

        // Curve names.
        public static Name Nistp265 => new Name("nistp256");
    }
}