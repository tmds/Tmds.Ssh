// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using static System.Environment;

namespace Tmds.Ssh
{
    public sealed class HostKeyVerification : IHostKeyVerification
    {
        public static IHostKeyVerification TrustAll { get; } = new TrustAllVerification();
        public static HostKeyVerification Default { get; }

        static HostKeyVerification()
        {
            Default = new HostKeyVerification();
            Default.AddKnownHostsFile(UserKnownHostsFile);
            Default.AddKnownHostsFile(SystemKnownHostsFile);
        }

        public static string UserKnownHostsFile
            => Path.Combine(Environment.GetFolderPath(SpecialFolder.UserProfile, SpecialFolderOption.DoNotVerify), ".ssh", "known_hosts");

        public static string SystemKnownHostsFile
        {
            get
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return Path.Combine(Environment.GetFolderPath(SpecialFolder.CommonApplicationData, SpecialFolderOption.DoNotVerify), "ssh", "known_hosts");
                }
                else
                {
                    return "/etc/ssh/known_hosts";
                }
            }
        }

        private readonly struct HostPort : IEquatable<HostPort>
        {
            public readonly int Port;
            public readonly string Host;

            public HostPort(string host, int port)
            {
                Host = host;
                Port = port;
            }

            public bool Equals(HostPort other)
            {
                return Port.Equals(other.Port) && Host.Equals(other.Host);
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(Port, Host);
            }
        }

        private readonly Dictionary<HostPort, SshKey> _trustedHosts = new Dictionary<HostPort, SshKey>();
        private readonly List<string> _knownHostFiles = new List<string>();

        public void AddKnownHostsFile(string filename)
        {
            lock (_knownHostFiles)
            {
                if (!_knownHostFiles.Contains(filename))
                {
                    _knownHostFiles.Add(filename);
                }
            }
        }

        public void AddTrustedHost(string host, int port, SshKey key)
        {
            if (key == null)
            {
                ThrowHelper.ThrowArgumentNull(nameof(key));
            }

            lock (_trustedHosts)
            {
                _trustedHosts.Add(new HostPort(host, port), key);
            }
        }

        public ValueTask<HostKeyVerificationResult> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct)
        {
            SshKey key = connectionInfo.ServerKey!;

            var result = HostKeyVerificationResult.Unknown;

            lock (_trustedHosts)
            {
                if (_trustedHosts.TryGetValue(new HostPort(connectionInfo.Host, connectionInfo.Port), out SshKey expectedKey))
                {
                    if (expectedKey.Equals(connectionInfo.ServerKey!))
                    {
                        return new ValueTask<HostKeyVerificationResult>(HostKeyVerificationResult.Trusted);
                    }
                    else
                    {
                        result = HostKeyVerificationResult.Changed;
                    }
                }
            }

            string? ip = connectionInfo.IPAddress?.ToString();

            lock (_knownHostFiles)
            {
                foreach (var knownHostFile in _knownHostFiles)
                {
                    HostKeyVerificationResult knownHostResult = KnownHostsFile.CheckHost(knownHostFile, connectionInfo.Host, ip, connectionInfo.Port, connectionInfo.ServerKey!);
                    if (knownHostResult == HostKeyVerificationResult.Revoked)
                    {
                        result = HostKeyVerificationResult.Revoked;
                        break;
                    }
                    if (knownHostResult == HostKeyVerificationResult.Unknown)
                    {
                        continue;
                    }

                    if (knownHostResult == HostKeyVerificationResult.Trusted ||
                        result == HostKeyVerificationResult.Unknown)
                    {
                        result = knownHostResult;
                    }
                }
            }

            return new ValueTask<HostKeyVerificationResult>(result);
        }

        private sealed class TrustAllVerification : IHostKeyVerification
        {
            public ValueTask<HostKeyVerificationResult> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct)
            {
                return new ValueTask<HostKeyVerificationResult>(HostKeyVerificationResult.Trusted);
            }
        }
    }
}
