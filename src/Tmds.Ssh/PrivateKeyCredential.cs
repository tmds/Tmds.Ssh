// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh;

public sealed class PrivateKeyCredential : Credential
{
    internal string FilePath { get; }
    internal string? Password { get; }

    public PrivateKeyCredential(string path, string? password = null)
    {
        FilePath = path ?? throw new ArgumentNullException(nameof(path));
        Password = password;
    }
}
