// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;

namespace Tmds.Ssh;

public sealed partial class SshClientSettings
{
    private static IReadOnlyList<Credential> CreateDefaultCredentials()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
        return
        [
            // new PrivateKeyCredential(Path.Combine(home, ".ssh", "id_ed25519")),
            // new PrivateKeyCredential(Path.Combine(home, ".ssh", "id_ecdsa")),
            new PrivateKeyCredential(Path.Combine(home, ".ssh", "id_rsa"))
        ];
    }
}
