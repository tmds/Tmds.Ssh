// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    sealed public class PasswordCredential : Credential
    {
        public PasswordCredential(string username, string password)
        {
            UserName = username ?? throw new ArgumentNullException(nameof(username));
            Password = password ?? throw new ArgumentNullException(nameof(password));
        }

        internal string UserName { get; }
        internal string Password { get; }
    }
}
