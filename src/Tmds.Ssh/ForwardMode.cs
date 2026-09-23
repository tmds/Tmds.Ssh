// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Specifies whether forwarding is enabled and how setup failures are handled.
/// </summary>
public enum ForwardMode
{
    /// <summary>
    /// Do not forward.
    /// </summary>
    Off,

    /// <summary>
    /// Forward. Log and continue when setup fails.
    /// </summary>
    Request,

    /// <summary>
    /// Forward. Fail when setup fails.
    /// </summary>
    Require,
}
