// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

sealed class HostKeyVerification : IHostKeyVerification
{
    private readonly HostAuthentication? _hostAuthentication;
    private readonly string? _updateKnownHostsFile;
    private readonly TrustedHostKeys _knownHostKeys;
    private readonly bool _hashKnownHosts;
    private readonly ILogger<SshClient> _logger;

    public HostKeyVerification(TrustedHostKeys knownHostKeys, HostAuthentication? hostAuthentication, string? updateKnownHostsFile, bool hashKnownHost, ILogger<SshClient> logger)
    {
        _knownHostKeys = knownHostKeys;
        _hostAuthentication = hostAuthentication;
        _updateKnownHostsFile = updateKnownHostsFile;
        _hashKnownHosts = hashKnownHost;
        _logger = logger;
    }

    public async ValueTask VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct)
    {
        HostKey serverKey = connectionInfo.ServerKey!;

        KnownHostResult result = _knownHostKeys.IsTrusted(serverKey.SshKey);
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

                    if (!string.IsNullOrEmpty(_updateKnownHostsFile))
                    {
                        KnownHostsFile.AddKnownHost(_updateKnownHostsFile, connectionInfo.HostName, connectionInfo.Port, serverKey, _hashKnownHosts);
                        _logger.ServerKeyAddKnownHost(connectionInfo.HostName, serverKey.Type, serverKey.SHA256FingerPrint, _updateKnownHostsFile);
                    }

                    return;
                }
            }
        }

        if (!isTrusted)
        {
            string message = $"The key type {serverKey.Type} SHA256:{serverKey.SHA256FingerPrint} is not trusted.";
            throw new ConnectFailedException(ConnectFailedReason.UntrustedPeer, message, connectionInfo);
        }
    }
}
