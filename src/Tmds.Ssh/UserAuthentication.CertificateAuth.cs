// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    public sealed class CertificateAuth
    {
        public static async Task<AuthResult> TryAuthenticate(CertificateCredential credential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            SshKeyData certificate;
            SshKeyData publicKey;
            try
            {
                (certificate, publicKey) = ClientCertificateParser.ParseClientCertificateFile(credential.Path);
                if (certificate.IsDefault)
                {
                    logger.ClientCertificateNotFound(credential.Path);
                    return AuthResult.Skipped;
                }
            }
            catch (Exception error)
            {
                logger.ClientCertificateCanNotLoad(credential.Path, error);
                return AuthResult.Skipped;
            }

            string keyIdentifier = credential.PrivateKey.Identifier;
            PrivateKeyCredential.Key key;
            try
            {
                key = await credential.PrivateKey.LoadKeyAsync(ct);
                if (key.PrivateKey is null)
                {
                    logger.PrivateKeyNotFound(keyIdentifier);
                    return AuthResult.Skipped;
                }
            }
            catch (Exception error)
            {
                logger.PrivateKeyCanNotLoad(keyIdentifier, error);
                return AuthResult.Skipped;
            }

            AuthResult result;

            using (key.PrivateKey)
            {
                if (!key.PrivateKey.PublicKey.Equals(publicKey))
                {
                    logger.ClientCertificatePrivateKeyMismatch(credential.Path, keyIdentifier);
                    return AuthResult.Skipped;
                }

                result = await PublicKeyAuth.DoAuthAsync(keyIdentifier, key.PrivateKey, certificate, key.QueryKey, context, context.SupportedAcceptedPublicKeyAlgorithms, connectionInfo, logger, ct).ConfigureAwait(false);
            }

            return result;
        }
    }
}