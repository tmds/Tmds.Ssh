// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    // Holds information about connection.
    sealed class SshConnectionInfo
    {
        public string? ServerIdentificationString { get; internal set; }
        public string? ClientIdentificationString { get; internal set; }
        public byte[]? SessionId { get; internal set; }
    }
}