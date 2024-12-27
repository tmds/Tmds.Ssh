// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class SshAgentCredentials : Credential
{
    internal string? Address { get; }

    internal SshAgentCredentials(string? address)
    {
        Address = address;
    }

    public SshAgentCredentials() : this(null)
    { }
}
