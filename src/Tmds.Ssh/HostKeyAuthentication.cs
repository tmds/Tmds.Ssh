// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

sealed class HostKeyAuthentication : IHostKeyAuthentication
{
    private readonly HostAuthentication? _hostAuthentication;
    private readonly string? _updateKnownHostsFile;
    private readonly TrustedHostKeys _knownHostKeys;
    private readonly bool _hashKnownHosts;
    private readonly ILogger<SshClient> _logger;

    public HostKeyAuthentication(TrustedHostKeys knownHostKeys, HostAuthentication? hostAuthentication, string? updateKnownHostsFile, bool hashKnownHost, ILogger<SshClient> logger)
    {
        _knownHostKeys = knownHostKeys;
        _hostAuthentication = hostAuthentication;
        _updateKnownHostsFile = updateKnownHostsFile;
        _hashKnownHosts = hashKnownHost;
        _logger = logger;
    }

    public async ValueTask AuthenticateAsync(SshConnectionInfo connectionInfo, CancellationToken ct)
    {
        HostKey serverKey = connectionInfo.ServerKey!;
        bool isCertificate = serverKey.CertInfo is not null;

        KnownHostResult result = _knownHostKeys.IsTrusted(serverKey.SshKey, serverKey.CertInfo?.CAKey);
        bool isTrusted = result == KnownHostResult.Trusted;

        if (isTrusted)
        {
            _logger.ServerKeyIsKnownHost(connectionInfo.HostName, serverKey.Type, serverKey.SHA256FingerPrint);
            return;
        }
        else if (result == KnownHostResult.Revoked)
        { }
        else
        {
            if (_hostAuthentication is not null)
            {
                isTrusted = await _hostAuthentication(result, connectionInfo, ct);
                if (isTrusted)
                {
                    _logger.ServerKeyIsApproved(serverKey.Type, serverKey.SHA256FingerPrint);

                    // Don't update for certificates.
                    if (!isCertificate)
                    {
                        if (!string.IsNullOrEmpty(_updateKnownHostsFile))
                        {
                            KnownHostsFile.AddKnownHost(_updateKnownHostsFile, connectionInfo.HostName, connectionInfo.Port, serverKey, _hashKnownHosts);
                            _logger.ServerKeyAddKnownHost(connectionInfo.HostName, serverKey.Type, serverKey.SHA256FingerPrint, _updateKnownHostsFile);
                        }
                    }

                    return;
                }
            }
        }

        Debug.Assert(!isTrusted);
        SshKey key = isCertificate ? serverKey.CertInfo!.CAKey : serverKey.SshKey;
        string message = $"The {(isCertificate ? "CA " : "")}key {key.Type} SHA256:{key.GetSHA256FingerPrint()} is not trusted.";
        throw new ConnectFailedException(ConnectFailedReason.UntrustedPeer, message, connectionInfo);
    }
}
