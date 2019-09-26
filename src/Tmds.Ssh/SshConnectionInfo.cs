// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    // Holds information about connection.
    sealed class SshConnectionInfo
    {
        public string? IdentificationString { get; internal set; }
    }
}