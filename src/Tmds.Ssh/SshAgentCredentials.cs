// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Credential for SSH agent authentication.
/// </summary>
public sealed class SshAgentCredentials : Credential
{
    internal string? Address { get; }

    internal SshAgentCredentials(string? address)
    {
        Address = address;
    }

    /// <summary>
    /// Creates a credential for SSH agent authentication.
    /// </summary>
    public SshAgentCredentials() : this(null)
    { }
}
