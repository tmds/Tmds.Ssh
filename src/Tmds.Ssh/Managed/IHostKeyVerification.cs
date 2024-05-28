// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh.Managed;

interface IHostKeyVerification
{
    ValueTask<HostAuthenticationResult> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct);
}
