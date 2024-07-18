// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh;

sealed class HostKeyVerification : IHostKeyVerification
{
    private readonly HostAuthentication? _hostAuthentication;
    private readonly string? _updateKnownHostsFile;
    private readonly TrustedHostKeys _knownHostKeys;

    public HostKeyVerification(TrustedHostKeys knownHostKeys, HostAuthentication? hostAuthentication, string? updateKnownHostsFile)
    {
        _knownHostKeys = knownHostKeys;
        _hostAuthentication = hostAuthentication;
        _updateKnownHostsFile = updateKnownHostsFile;
    }

    public async ValueTask<bool> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct)
    {
        HostKey serverKey = connectionInfo.ServerKey!;

        KnownHostResult result = _knownHostKeys.IsTrusted(serverKey);
        bool isTrusted = result == KnownHostResult.Trusted;

        if (!isTrusted && result != KnownHostResult.Revoked)
        {
            if (_hostAuthentication is not null)
            {
                isTrusted = await _hostAuthentication(result, connectionInfo, ct);
                if (isTrusted && !string.IsNullOrEmpty(_updateKnownHostsFile))
                {
                    KnownHostsFile.AddKnownHost(_updateKnownHostsFile, connectionInfo.HostName, connectionInfo.Port, serverKey);
                }
            }
        }

        return isTrusted;
    }
}
