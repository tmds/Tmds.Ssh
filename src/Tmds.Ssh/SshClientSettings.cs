// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // This class gathers settings for SshClient in a separate object.
    public sealed class SshClientSettings
    {
        public TimeSpan ConnectTimeout { get; set; }
        public string Host { get; set; }
        public int Port { get; set; }
    }
}
