// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    public sealed class SshConnectionInfo
    {
        public PublicKey ServerKey { get; internal set; } = null!;
        public string Host { get; internal set; } = string.Empty;
        public int Port { get; internal set; }
    }
}