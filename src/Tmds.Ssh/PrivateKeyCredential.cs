// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh;

public sealed class PrivateKeyCredential : Credential
{
    internal string FilePath { get; }

    internal Func<string?> PasswordPrompt { get; }

    public PrivateKeyCredential(string path, string? password = null) : this(path, () => password)
    { }

    public PrivateKeyCredential(string path, Func<string?> passwordPrompt)
    {
        FilePath = path ?? throw new ArgumentNullException(nameof(path));
        PasswordPrompt = passwordPrompt;
    }
}
