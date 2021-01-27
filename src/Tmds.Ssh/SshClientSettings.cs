// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;

namespace Tmds.Ssh
{
    // This class gathers settings for SshClient in a separate object.
    public sealed class SshClientSettings
    {
        internal SshClientSettings(string destination)
        {
            if (destination == null)
            {
                throw new ArgumentNullException(nameof(destination));
            }
            string host = destination;
            int port = 22;
            int colonPos = host.IndexOf(":");
            if (colonPos != -1)
            {
                port = int.Parse(host.Substring(colonPos + 1));
                host = host.Substring(0, colonPos);
            }
            int atPos = host.IndexOf("@");
            string username;
            if (atPos != -1)
            {
                username = host.Substring(0, atPos);
                host = host.Substring(atPos + 1);
            }
            else
            {
                username = Environment.UserName;
            }

            UserName = username;
            Host = host;
            Port = port;
        }

        public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15); // TODO
        internal string UserName { get; set; }
        internal string Host { get; set; }
        internal int Port { get; set; } = 22;
        public List<Credential> Credentials { get; } = new List<Credential>();
    }
}
