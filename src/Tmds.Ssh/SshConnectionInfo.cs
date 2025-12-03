// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;

namespace Tmds.Ssh;

/// <summary>
/// Information about an active SSH connection.
/// </summary>
public sealed class SshConnectionInfo
{
    internal SshConnectionInfo() { }

    /// <summary>
    /// Gets the server host key.
    /// </summary>
    public HostKey ServerKey { get; internal set; } = null!;

    /// <summary>
    /// Gets the server hostname.
    /// </summary>
    public string HostName { get; internal set; } = string.Empty;

    /// <summary>
    /// Gets the username.
    /// </summary>
    public string UserName { get; internal set; } = string.Empty;

    /// <summary>
    /// Gets the server port.
    /// </summary>
    public int Port { get; internal set; }

    /// <summary>
    /// Gets whether this is a proxy connection.
    /// </summary>
    public bool IsProxy { get; internal set; }

    internal bool UseStrictKex { get; set; }
    internal byte[]? SessionId { get; set; }
    internal string? ClientIdentificationString { get; set; }
    internal string? ServerIdentificationString { get; set; }
    internal IPAddress? IPAddress { get; set; }
    internal bool IsBatchMode { get; set; }
}
