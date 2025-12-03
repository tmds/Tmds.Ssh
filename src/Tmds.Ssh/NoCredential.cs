// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Credential for 'none' authentication method.
/// </summary>
public sealed class NoCredential : Credential
{
    /// <summary>
    /// Creates a credential for the 'none' authentication method.
    /// </summary>
    public NoCredential()
    { }
}
