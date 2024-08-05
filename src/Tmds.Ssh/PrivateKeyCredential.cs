// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Text;

namespace Tmds.Ssh;

public sealed class PrivateKeyCredential : Credential
{
    internal string FilePath { get; }
    internal byte[] Passphrase { get; }

    public PrivateKeyCredential(string path, string? passphrase = null)
    {
        FilePath = path ?? throw new ArgumentNullException(nameof(path));
        Passphrase = string.IsNullOrEmpty(passphrase) ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(passphrase);
    }
}
