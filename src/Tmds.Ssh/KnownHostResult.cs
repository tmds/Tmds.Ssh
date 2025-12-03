// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Result of host key verification against known hosts.
/// </summary>
public enum KnownHostResult
{
    /// <summary>
    /// Key is trusted for the host.
    /// </summary>
    Trusted,

    /// <summary>
    /// Key is revoked for the host.
    /// </summary>
    Revoked,

    /// <summary>
    /// A different key is known for the host.
    /// </summary>
    Changed,

    /// <summary>
    /// No key is known for the host.
    /// </summary>
    Unknown,
}
