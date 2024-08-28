// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class PasswordCredential : Credential
{
    private readonly Func<string?> _getPassword;

    internal string? GetPassword() => _getPassword();

    public PasswordCredential(string password) : this(() => password)
    { }

    public PasswordCredential(Func<string?> passwordPrompt)
    {
        _getPassword = passwordPrompt;
    }
}

