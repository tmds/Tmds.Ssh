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

    public PasswordCredential(Func<string?> passwordPrompt) :
        this((PasswordPromptContext ctx, CancellationToken ct) => ValueTask.FromResult(ctx.Attempt > 1 ? null : passwordPrompt()))
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

    internal PasswordPromptContext(SshConnectionInfo connectionInfo, int attempt)
    {
        ConnectionInfo = connectionInfo;
        Attempt = attempt;
    }

    public static ValueTask<string?> ReadPasswordFromConsole(string? prompt = null)
    {
        if (Console.IsInputRedirected || Console.IsOutputRedirected)
        {
            return ValueTask.FromResult((string?)null);
        }

        if (!string.IsNullOrEmpty(prompt))
        {
            Console.Write(prompt);
        }

        var password = string.Empty;
        ConsoleKeyInfo key;
        do
        {
            key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            else if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                {
                    password = password[..^1];
                }
            }
            else if (key.KeyChar != '\0')
            {
                password += key.KeyChar;
            }
        } while (true);
        return ValueTask.FromResult((string?)password);
    }
}