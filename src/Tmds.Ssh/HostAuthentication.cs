// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Context for host key authentication.
/// </summary>
public struct HostAuthenticationContext
{
    internal HostAuthenticationContext(KnownHostResult knownHostResult, SshConnectionInfo connectionInfo)
    {
        KnownHostResult = knownHostResult;
        ConnectionInfo = connectionInfo;
    }

    /// <summary>
    /// Gets the known host verification result.
    /// </summary>
    public KnownHostResult KnownHostResult { get; }

    /// <summary>
    /// Gets the SSH connection information.
    /// </summary>
    public SshConnectionInfo ConnectionInfo { get; }

    /// <summary>
    /// Returns whether batch (non-interactive) mode is enabled.
    /// </summary>
    /// <remarks>
    /// In batch mode the <see cref="HostAuthentication"/> delegate mustn't make interactive prompts.
    /// </remarks>
    public bool IsBatchMode => ConnectionInfo.IsBatchMode;
}

/// <summary>
/// Delegate for authenticating host keys.
/// </summary>
/// <param name="context">The host authentication context.</param>
/// <param name="cancellationToken">Token to cancel the operation.</param>
/// <returns><see langword="true"/> to accept the host key, <see langword="false"/> to reject.</returns>
public delegate ValueTask<bool> HostAuthentication(HostAuthenticationContext context, CancellationToken cancellationToken);
