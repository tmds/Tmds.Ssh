// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public abstract class HostKeyVerification
    {
        public static HostKeyVerification TrustAll { get; } = new TrustAllVerification();

        public abstract ValueTask<HostKeyVerificationResult> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct);

        private sealed class TrustAllVerification : HostKeyVerification
        {
            public override ValueTask<HostKeyVerificationResult> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct)
            {
                return new ValueTask<HostKeyVerificationResult>(HostKeyVerificationResult.Trusted);
            }
        }
    }
}
