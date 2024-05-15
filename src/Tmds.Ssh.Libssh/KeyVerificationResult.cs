// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    public enum KeyVerificationResult
    {
        Trusted,      // Server is known and has not changed.
        AddKnownHost, // Request to add host to the known hosts file.

        Revoked, // Key is revoked.
        Error,   // Could not verify due to an error.

        Changed, // Server key has changed.
        Unknown, // Server is not known.
    }
}