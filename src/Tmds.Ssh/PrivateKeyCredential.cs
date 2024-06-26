// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh;

public sealed class PrivateKeyCredential : Credential
{
    internal string FilePath { get; }

    public PrivateKeyCredential(string path)
    {
        FilePath = path ?? throw new ArgumentNullException(nameof(path));
    }
}
