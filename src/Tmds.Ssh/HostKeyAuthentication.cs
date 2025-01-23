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
        bool isCertificate = serverKey.IssuerKey is not null;
#if DEBUG
        // The certificate (if present) has already been validated (expiration, matching host, ...).
        Debug.Assert(serverKey.CertInfo?.IsVerified != false);
#endif

        KnownHostResult result = _knownHostKeys.IsTrusted(serverKey.RawKey, serverKey.CertInfo?.CAKey, serverKey.CertInfo?.SignedKey);
        bool isTrusted = result == KnownHostResult.Trusted;

        if (isTrusted)
        {
            _logger.ServerKeyIsKnownHost(connectionInfo.HostName, serverKey.RawKey.Type, serverKey.RawKey.SHA256FingerPrint);
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
                    _logger.ServerKeyIsApproved(serverKey.RawKey.Type, serverKey.RawKey.SHA256FingerPrint);

                    // Don't update for certificates.
                    if (!isCertificate)
                    {
                        if (!string.IsNullOrEmpty(_updateKnownHostsFile))
                        {
                            SshKey publicKey = serverKey.PublicKey;
                            KnownHostsFile.AddKnownHost(_updateKnownHostsFile, connectionInfo.HostName, connectionInfo.Port, publicKey, _hashKnownHosts);
                            _logger.ServerKeyAddKnownHost(connectionInfo.HostName, publicKey.Type, publicKey.SHA256FingerPrint, _updateKnownHostsFile);
                        }
                    }

                    return;
                }
            }
        }

        Debug.Assert(!isTrusted);
        SshKey key = serverKey.IssuerKey ?? serverKey.RawKey;
        string message = $"The {(isCertificate ? "CA " : "")}key {key.Type} SHA256:{key.SHA256FingerPrint} is not trusted.";
        throw new ConnectFailedException(ConnectFailedReason.UntrustedPeer, message, connectionInfo);
    }
}
