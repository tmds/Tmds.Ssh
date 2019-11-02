// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    // Holds information about connection.
    public sealed class SshConnectionInfo
    {
        internal string? ServerIdentificationString { get; set; }
        internal string? ClientIdentificationString { get; set; }
        internal byte[]? SessionId { get; set; }

        public string Host { get; internal set; } = string.Empty;
        public int Port { get; internal set; }
        public SshKey? SshKey { get; internal set; }
    }
}