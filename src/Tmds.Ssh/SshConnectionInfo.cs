// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;

namespace Tmds.Ssh;

public sealed class SshConnectionInfo
{
    internal SshConnectionInfo() { }
    public HostKey ServerKey { get; internal set; } = null!;
    public string HostName { get; internal set; } = string.Empty;
    public string UserName { get; internal set; } = string.Empty;
    public int Port { get; internal set; }
    public bool IsProxy { get; internal set; }

    internal bool UseStrictKex { get; set; }
    internal byte[]? SessionId { get; set; }
    internal string? ClientIdentificationString { get; set; }
    internal string? ServerIdentificationString { get; set; }
    internal IPAddress? IPAddress { get; set; }
}
