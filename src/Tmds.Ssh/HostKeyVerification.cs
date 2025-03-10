// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

static class HostKeyVerification
{
    public static void CheckAllowedHostKeyAlgoritms(SshConnectionInfo connectionInfo, SshKeyData public_host_key, IReadOnlyList<Name> allowedHostKeyAlgorithms)
    {
        Name hostKeyType = public_host_key.Type;
        // Verify the HostKey is permitted by HostKeyAlgorithms.
        if (!IsAlgorithmAllowed(AlgorithmNames.GetHostKeyAlgorithmsForHostKeyType(ref hostKeyType), allowedHostKeyAlgorithms))
        {
            // Don't throw ConnectFailedException as we haven't assigned SshConnectionInfo.ServerKey.
            throw new SshConnectionException($"Server host key type {public_host_key.Type} is not accepted.");
        }

        HostKey hostKey = new HostKey(public_host_key);
        connectionInfo.ServerKey = hostKey;
    }

    public static void CheckMinimumRSAKeySize(SshConnectionInfo connectionInfo, int minimumRSAKeySize)
    {
        {
            if (connectionInfo.ServerKey.PublicKey is RsaPublicKey rsaPublicKey && rsaPublicKey.KeySize < minimumRSAKeySize)
            {
                throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"Server RSA key size {rsaPublicKey.KeySize} is less than {minimumRSAKeySize}.", connectionInfo);
            }
        }
        {
            if (connectionInfo.ServerKey.CertificateInfo?.CAPublicKey is RsaPublicKey rsaPublicKey && rsaPublicKey.KeySize < minimumRSAKeySize)
            {
                throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"Server CA RSA key size {rsaPublicKey.KeySize} is less than {minimumRSAKeySize}.", connectionInfo);
            }
        }
    }

    public static void CheckCertificate(SshConnectionInfo connectionInfo, HostCertificateInfo certInfo, IReadOnlyList<Name> allowedCASignaturelgorithms)
    {
        // Check if the certificate signature algorithm is allowed.
        Name[] keySignatureAlgorithms = AlgorithmNames.GetSignatureAlgorithmsForKeyType(certInfo.IssuerKey.SshKeyData.Type);
        if (!IsAlgorithmAllowed(keySignatureAlgorithms, allowedCASignaturelgorithms))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"Server CA signature algorithm {certInfo.IssuerKey.Type} is not accepted.", connectionInfo);
        }

        // Critical options musn't be ignored.
        if (certInfo.HasCriticalOptions)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"Server certificate includes unknown critical options.", connectionInfo);
        }

        // Check if the certificate matches the hostname.
        if (certInfo.Principals.Count != 0 && !certInfo.Principals.Contains(connectionInfo.HostName))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"Server certificate does not match the connection hostname.", connectionInfo);
        }

        // Check the expiration.
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (now < certInfo.ValidAfter || now >= certInfo.ValidBefore)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"Server certificate has expired.", connectionInfo);
        }

        // Check the signature.
        var reader = new SequenceReader(certInfo.Signature);
        Name algorithmName = reader.ReadName();
        ReadOnlySequence<byte> signature = reader.ReadStringAsBytes();
        reader.ReadEnd();

        if (!allowedCASignaturelgorithms.Contains(algorithmName))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"CA signature type {algorithmName} is not accepted.", connectionInfo);
        }

        if (!certInfo.CAPublicKey.VerifySignature(algorithmName, certInfo.SignedData.Span, signature))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Server certificate signature does not match CA key.", connectionInfo);
        }

#if DEBUG
        certInfo.IsVerified = true;
#endif
    }

    private static bool IsAlgorithmAllowed(ReadOnlySpan<Name> availableAlgorithms, IReadOnlyList<Name> allowedAlgorithms)
    {
        foreach (var algorithm in availableAlgorithms)
        {
            if (allowedAlgorithms.Contains(algorithm))
            {
                return true;
            }
        }
        return false;
    }
}
