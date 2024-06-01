// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using static System.Environment;

namespace Tmds.Ssh;

sealed class HostKeyVerification : IHostKeyVerification
{
    private readonly SshClientSettings _sshClientSettings;

    public HostKeyVerification(SshClientSettings sshClientSettings)
    {
        _sshClientSettings = sshClientSettings;
    }

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

    public async ValueTask<bool> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct)
    {
        HostKey key = connectionInfo.ServerKey!;

        KnownHostResult result = KnownHostResult.Unknown;

        string? ip = connectionInfo.IPAddress?.ToString();

        string? settingsKnownHostsFile = _sshClientSettings.KnownHostsFilePath;
        string? globalKnownHostsFile = _sshClientSettings.CheckGlobalKnownHostsFile ? SystemKnownHostsFile : null;

        foreach (var knownHostFile in new string?[] { settingsKnownHostsFile, globalKnownHostsFile })
        {
            if (string.IsNullOrEmpty(knownHostFile))
            {
                continue;
            }

            KnownHostResult knownHostResult = KnownHostsFile.CheckHost(knownHostFile, connectionInfo.Host, ip, connectionInfo.Port, connectionInfo.ServerKey!);
            if (knownHostResult == KnownHostResult.Revoked)
            {
                result = KnownHostResult.Revoked;
                break;
            }
            if (knownHostResult == KnownHostResult.Unknown)
            {
                continue;
            }

            if (knownHostResult == KnownHostResult.Trusted ||
                result == KnownHostResult.Unknown)
            {
                result = knownHostResult;
            }
        }

        bool isTrusted = result == KnownHostResult.Trusted;

        if (!isTrusted && result != KnownHostResult.Revoked)
        {
            HostAuthentication? authentication = _sshClientSettings.HostAuthentication;
            if (authentication is not null)
            {
                isTrusted = await authentication(result, connectionInfo, ct);
                if (isTrusted && _sshClientSettings.UpdateKnownHostsFile && !string.IsNullOrEmpty(settingsKnownHostsFile))
                {
                    KnownHostsFile.AddKnownHost(settingsKnownHostsFile, connectionInfo.Host, connectionInfo.Port, connectionInfo.ServerKey);
                }
            }
        }

        return isTrusted;
    }
}
