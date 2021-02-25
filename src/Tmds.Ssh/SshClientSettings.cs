// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public delegate ValueTask<KeyVerificationResult> KeyVerification(KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken);

    // This class gathers settings for SshClient in a separate object.
    public sealed class SshClientSettings
    {
        public SshClientSettings()
        { }

        internal void ConfigureForDestination(string destination)
        {
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

        public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);
        public string UserName { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; } = 22;
        public List<Credential> Credentials { get; } = new List<Credential>();
        public string? KnownHostsFile { get; set; } = DefaultKnownHostsFile;
        public bool CheckGlobalKnownHostsFile { get; set; } = true;
        public KeyVerification? KeyVerification { get; set; }

        private static string DefaultKnownHostsFile
            => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments, Environment.SpecialFolderOption.DoNotVerify),
                            ".ssh",
                            "known_hosts");
    }
}
