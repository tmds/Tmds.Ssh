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
            // Default.AddKnownHostsFile(UserKnownHostsFile);
            // Default.AddKnownHostsFile(SystemKnownHostsFile);
        }

        private static string UserKnownHostsFile
            => Path.Combine(Environment.GetFolderPath(SpecialFolder.UserProfile, SpecialFolderOption.DoNotVerify), ".ssh", "known_hosts");

        private static string SystemKnownHostsFile
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

        private readonly HashSet<SshKey> _trustedKeys = new HashSet<SshKey>();

        // public void AddKnownHostsFile(string filename)
        //     => throw new NotSupportedException();

        public void AddTrustedKey(SshKey key)
        {
            if (key == null)
            {
                ThrowHelper.ThrowArgumentNull(nameof(key));
            }

            lock (_trustedKeys)
            {
                _trustedKeys.Add(key);
            }
        }

        public ValueTask<HostKeyVerificationResult> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct)
        {
            SshKey key = connectionInfo.ServerKey!;

            lock (_trustedKeys)
            {
                if (_trustedKeys.Contains(key))
                {
                    return new ValueTask<HostKeyVerificationResult>(HostKeyVerificationResult.Trusted);
                }
            }

            return new ValueTask<HostKeyVerificationResult>(HostKeyVerificationResult.Unknown);
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
