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
        bool hasCertificate = serverKey.CertificateInfo is not null;
#if DEBUG
        // The certificate (if present) has already been validated (expiration, matching host, ...).
        Debug.Assert(serverKey.CertificateInfo?.IsVerified != false);
#endif

        KnownHostResult result = _knownHostKeys.IsTrusted(serverKey.Key, serverKey.CertificateInfo?.IssuerKey);
        bool isTrusted = result == KnownHostResult.Trusted;

        if (isTrusted)
        {
            _logger.ServerKeyIsKnownHost(connectionInfo.HostName, serverKey.Key.Type, serverKey.Key.SHA256FingerPrint);
            return;
        }
        else if (result == KnownHostResult.Revoked)
        { }
        else
        {
            if (_hostAuthentication is not null)
            {
                var ctx = new HostAuthenticationContext(result, connectionInfo);
                isTrusted = await _hostAuthentication(ctx, ct);
                if (isTrusted)
                {
                    _logger.ServerKeyIsApproved(serverKey.Key.Type, serverKey.Key.SHA256FingerPrint);

                    // Don't update for certificates.
                    if (!hasCertificate)
                    {
                        if (!string.IsNullOrEmpty(_updateKnownHostsFile))
                        {
                            PublicKey publicKey = serverKey.Key;
                            KnownHostsFile.AddKnownHost(_updateKnownHostsFile, connectionInfo.HostName, connectionInfo.Port, publicKey, _hashKnownHosts);
                            _logger.ServerKeyAddKnownHost(connectionInfo.HostName, publicKey.Type, publicKey.SHA256FingerPrint, _updateKnownHostsFile);
                        }
                    }

                    return;
                }
            }
        }

        Debug.Assert(!isTrusted);
        HostCertificateInfo? certInfo = serverKey.CertificateInfo;
        PublicKey? issuerKey = certInfo?.IssuerKey;
        string signedByCA = issuerKey is null ? "" : $" (signed by CA {issuerKey.Type} SHA256:{issuerKey.SHA256FingerPrint} with id '{certInfo!.Identifier}' and serial '{certInfo.SerialNumber}')";
        string message = $"The key {serverKey.Key.Type} SHA256:{serverKey.Key.SHA256FingerPrint}{signedByCA} is not trusted.";
        throw new ConnectFailedException(ConnectFailedReason.UntrustedPeer, message, connectionInfo);
    }
}
