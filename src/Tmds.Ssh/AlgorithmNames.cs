// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    static class AlgorithmNames
    {
        public static Name None => new Name("none");

        // Key exchange algorithms
        public static Name EcdhSha2Nistp256 => new Name("ecdh-sha2-nistp256");

        // Host key algorithms.
        public static Name SshRsa => new Name("ssh-rsa");

        // Encryption algorithms.
        public static Name Aes256Cbc => new Name("aes256-cbc");

        // Mac algorithms.
        public static Name HMacSha2_256 => new Name("hmac-sha2-256");
    }
}