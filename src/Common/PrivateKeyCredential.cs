// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    public sealed class PrivateKeyCredential : Credential
    {
        public PrivateKeyCredential(string filePath)
        {
            FilePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        }

        internal string FilePath { get; }
    }
}
