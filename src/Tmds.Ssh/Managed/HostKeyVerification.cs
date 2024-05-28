// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using static System.Environment;

namespace Tmds.Ssh.Managed;

sealed class HostKeyVerification : IHostKeyVerification
{
    private readonly SshClientSettings _sshClientSettings;

    public HostKeyVerification(SshClientSettings sshClientSettings)
    {
        _sshClientSettings = sshClientSettings;
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

    public async ValueTask<HostAuthenticationResult> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct)
    {
        HostKey key = connectionInfo.ServerKey!;

        var result = HostAuthenticationResult.Unknown;

        string? ip = connectionInfo.IPAddress?.ToString();

        string? settingsKnownHostsFile = _sshClientSettings.KnownHostsFilePath;
        string? globalKnownHostsFile = _sshClientSettings.CheckGlobalKnownHostsFile ? SystemKnownHostsFile : null;

        foreach (var knownHostFile in new string?[] { settingsKnownHostsFile, globalKnownHostsFile })
        {
            if (string.IsNullOrEmpty(knownHostFile))
            {
                continue;
            }

            HostAuthenticationResult knownHostResult = KnownHostsFile.CheckHost(knownHostFile, connectionInfo.Host, ip, connectionInfo.Port, connectionInfo.ServerKey!);
            if (knownHostResult == HostAuthenticationResult.Revoked)
            {
                result = HostAuthenticationResult.Revoked;
                break;
            }
            if (knownHostResult == HostAuthenticationResult.Unknown)
            {
                continue;
            }

            if (knownHostResult == HostAuthenticationResult.Trusted ||
                result == HostAuthenticationResult.Unknown)
            {
                result = knownHostResult;
            }
        }

        if (result == HostAuthenticationResult.Changed ||
            result == HostAuthenticationResult.Unknown)
        {
            HostAuthentication? keyVerification = _sshClientSettings.HostAuthentication;
            if (keyVerification is not null)
            {
                result = await keyVerification(result, connectionInfo, ct);
                if (result == HostAuthenticationResult.AddKnownHost)
                {
                    if (!string.IsNullOrEmpty(settingsKnownHostsFile))
                    {
                        try
                        {
                            KnownHostsFile.AddKnownHost(settingsKnownHostsFile, connectionInfo.Host, connectionInfo.Port, connectionInfo.ServerKey);
                        }
                        catch
                        {
                            /* Ignore errors */
                        }
                    }
                    result = HostAuthenticationResult.Trusted;
                }
            }
        }

        return result;
    }
}
