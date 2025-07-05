// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public struct HostAuthenticationContext
{
    internal HostAuthenticationContext(KnownHostResult knownHostResult, SshConnectionInfo connectionInfo)
    {
        KnownHostResult = knownHostResult;
        ConnectionInfo = connectionInfo;
    }

    public KnownHostResult KnownHostResult { get; }
    public SshConnectionInfo ConnectionInfo { get; }
}

public delegate ValueTask<bool> HostAuthentication(HostAuthenticationContext context, CancellationToken cancellationToken);
