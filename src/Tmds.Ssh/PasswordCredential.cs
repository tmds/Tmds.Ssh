// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Delegate for prompting the user for a password.
/// </summary>
/// <param name="context">The password prompt context.</param>
/// <param name="cancellationToken">Token to cancel the operation.</param>
/// <returns>The password, or <see langword="null"/> to stop password authentication.</returns>
public delegate ValueTask<string?> PasswordPrompt(PasswordPromptContext context, CancellationToken cancellationToken);

/// <summary>
/// Credential for password authentication.
/// </summary>
public sealed class PasswordCredential : Credential
{
    private readonly PasswordPrompt _passwordPrompt;

    internal ValueTask<string?> GetPasswordAsync(PasswordPromptContext ctx, CancellationToken ct) => _passwordPrompt(ctx, ct);

    /// <summary>
    /// Creates a password credential with a fixed password.
    /// </summary>
    /// <param name="password">The password.</param>
    public PasswordCredential(string password) :
        this((PasswordPromptContext ctx, CancellationToken ct) => ValueTask.FromResult(ctx.Attempt > 1 ? null : password))
    { }

    /// <summary>
    /// Creates a password credential with a prompt callback.
    /// </summary>
    /// <param name="passwordPrompt">The <see cref="PasswordPrompt"/> callback.</param>
    public PasswordCredential(PasswordPrompt passwordPrompt)
    {
        _passwordPrompt = passwordPrompt;
    }
}

/// <summary>
/// Context for password prompts.
/// </summary>
public struct PasswordPromptContext
{
    private readonly ConnectCancellation? _connectCancellation;

    /// <summary>
    /// Gets the SSH connection information.
    /// </summary>
    public SshConnectionInfo ConnectionInfo { get; }

    /// <summary>
    /// Gets the attempt number (1-based).
    /// </summary>
    public int Attempt { get; }

    /// <summary>
    /// Returns whether this prompt is non-interactive.
    /// </summary>
    /// <remarks>
    /// Returns <see langword="true"/> when the connection is in batch mode or when the connection is an automatic reconnect.
    /// When <see langword="true"/>, the <see cref="PasswordPrompt"/> delegate mustn't make interactive prompts.
    /// </remarks>
    public bool IsNonInteractive => ConnectionInfo.IsNonInteractive;

    /// <summary>
    /// Suspends the connect timeout so it does not expire while waiting for user interaction.
    /// </summary>
    public void SuspendConnectTimeout() => _connectCancellation?.SuspendTimeout();

    /// <summary>
    /// Resumes the connect timeout after it was suspended.
    /// </summary>
    public void ResumeConnectTimeout() => _connectCancellation?.ResumeTimeout();

    internal PasswordPromptContext(SshConnectionInfo connectionInfo, int attempt, ConnectCancellation connectCancellation)
    {
        ConnectionInfo = connectionInfo;
        Attempt = attempt;
        _connectCancellation = connectCancellation;
    }
}
