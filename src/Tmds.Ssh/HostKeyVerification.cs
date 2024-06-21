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
    private readonly SshClientSettings _sshClientSettings;
    private readonly TrustedHostKeys _knownHostKeys;

    public HostKeyVerification(SshClientSettings sshClientSettings, TrustedHostKeys knownHostKeys)
    {
        _sshClientSettings = sshClientSettings;
        _knownHostKeys = knownHostKeys;
    }

    public async ValueTask<bool> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct)
    {
        HostKey serverKey = connectionInfo.ServerKey!;

        KnownHostResult result = _knownHostKeys.IsTrusted(serverKey);
        bool isTrusted = result == KnownHostResult.Trusted;

        if (!isTrusted && result != KnownHostResult.Revoked)
        {
            HostAuthentication? authentication = _sshClientSettings.HostAuthentication;
            if (authentication is not null)
            {
                isTrusted = await authentication(result, connectionInfo, ct);
                string? settingsKnownHostsFile = _sshClientSettings.KnownHostsFilePath;
                if (isTrusted && _sshClientSettings.UpdateKnownHostsFile && !string.IsNullOrEmpty(settingsKnownHostsFile))
                {
                    KnownHostsFile.AddKnownHost(settingsKnownHostsFile, connectionInfo.Host, connectionInfo.Port, serverKey);
                }
            }
        }

        return isTrusted;
    }
}
