// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Context for host key authentication.
/// </summary>
public struct HostAuthenticationContext
{
    private readonly ConnectCancellation? _connectCancellation;
    private readonly bool _isRekey;

    internal HostAuthenticationContext(KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, bool isRekey, ConnectCancellation? connectCancellation)
    {
        KnownHostResult = knownHostResult;
        ConnectionInfo = connectionInfo;
        _connectCancellation = connectCancellation;
        _isRekey = isRekey;
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
    /// Returns whether this authentication is non-interactive.
    /// </summary>
    /// <remarks>
    /// Returns <see langword="true"/> when the connection is in batch mode, when the authentication is for a key re-exchange,
    /// or when the connection is an automatic reconnect.
    /// When <see langword="true"/>, the <see cref="HostAuthentication"/> delegate mustn't make interactive prompts.
    /// </remarks>
    public bool IsNonInteractive => _isRekey || ConnectionInfo.IsNonInteractive;

    /// <inheritdoc cref="IsNonInteractive"/>
    [Obsolete($"Use {nameof(IsNonInteractive)} instead.")]
    public bool IsBatchMode => IsNonInteractive;

    /// <summary>
    /// Suspends the connect timeout so it does not expire while waiting for user interaction.
    /// </summary>
    public void SuspendConnectTimeout() => _connectCancellation?.SuspendTimeout();

    /// <summary>
    /// Resumes the connect timeout after it was suspended.
    /// </summary>
    public void ResumeConnectTimeout() => _connectCancellation?.ResumeTimeout();
}

/// <summary>
/// Delegate for authenticating host keys.
/// </summary>
/// <param name="context">The host authentication context.</param>
/// <param name="cancellationToken">Token to cancel the operation.</param>
/// <returns><see langword="true"/> to accept the host key, <see langword="false"/> to reject.</returns>
public delegate ValueTask<bool> HostAuthentication(HostAuthenticationContext context, CancellationToken cancellationToken);
