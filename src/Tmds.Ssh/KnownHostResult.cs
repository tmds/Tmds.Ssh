// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public enum KnownHostResult
{
    Trusted, // Server is known and has not changed.

    Revoked, // Key is revoked.

    Changed, // Server key has changed.
    Unknown, // Server is not known.
}
