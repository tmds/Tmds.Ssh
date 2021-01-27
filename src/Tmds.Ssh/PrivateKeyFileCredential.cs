// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    sealed public class PrivateKeyFileCredential : Credential
    {
        public PrivateKeyFileCredential(string filename)
        {
            FileName = filename ?? throw new ArgumentNullException(nameof(filename));
        }

        public string FileName { get; }
    }
}
