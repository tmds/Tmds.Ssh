// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;

namespace Tmds.Ssh
{
    // Holds information about connection.
    public sealed class SshConnectionInfo
    {
        internal byte[]? SessionId { get; set; }
        internal string? ClientIdentificationString { get; set; }

        public string? ServerIdentificationString { get; internal set; }
        public SshKey? ServerKey { get; internal set; }
        public HostKeyVerificationResult? KeyVerificationResult { get; internal set; }
        public IPAddress? IPAddress { get; internal set; }

        public string Host { get; internal set; } = string.Empty;
        public int Port { get; internal set; }
    }
}