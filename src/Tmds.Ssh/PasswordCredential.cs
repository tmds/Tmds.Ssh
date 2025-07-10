// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public delegate ValueTask<string?> PasswordPrompt(PasswordPromptContext context, CancellationToken cancellationToken);

public sealed class PasswordCredential : Credential
{
    private readonly PasswordPrompt _passwordPrompt;

    internal ValueTask<string?> GetPasswordAsync(PasswordPromptContext ctx, CancellationToken ct) => _passwordPrompt(ctx, ct);

    public PasswordCredential(string password) :
        this((PasswordPromptContext ctx, CancellationToken ct) => ValueTask.FromResult(ctx.Attempt > 1 ? null : password))
    { }

    public PasswordCredential(PasswordPrompt passwordPrompt)
    {
        _passwordPrompt = passwordPrompt;
    }
}

public struct PasswordPromptContext
{
    public SshConnectionInfo ConnectionInfo { get; }
    public int Attempt { get; }
    public bool IsBatchMode => ConnectionInfo.IsBatchMode;

    internal PasswordPromptContext(SshConnectionInfo connectionInfo, int attempt)
    {
        ConnectionInfo = connectionInfo;
        Attempt = attempt;
    }
}