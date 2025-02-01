// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    public sealed class CertificateAuth
    {
        public static async Task<AuthResult> TryAuthenticate(CertificateFileCredential credential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            if (!TryLoadCertificate(credential.Path, logger, out SshKeyData certificate, out SshKeyData publicKey))
            {
                return AuthResult.Skipped;
            }

            (SshAgent? sshAgent, PrivateKey? privateKey) = await FindMatchingPrivateKey(credential.Path, publicKey, credential.IdentityFiles, credential.SshAgent, context.SequencePool, logger, ct).ConfigureAwait(false);

            using (sshAgent)
            using (privateKey)
            {
                if (privateKey is null)
                {
                    return AuthResult.Skipped;
                }

                return await PublicKeyAuth.DoAuthAsync(credential.Path, privateKey, certificate, queryKey: sshAgent is not null, context, context.SupportedAcceptedPublicKeyAlgorithms, connectionInfo, logger, ct).ConfigureAwait(false);
            }
        }

        private static async ValueTask<(SshAgent? sshAgent, PrivateKey? privateKey)> FindMatchingPrivateKey(string credentialFilePath, SshKeyData publicKey, List<string>? identityFiles, SshAgentCredentials? sshAgentCredential, SequencePool sequencePool, ILogger<SshClient> logger, CancellationToken ct)
        {
            if (identityFiles is not null)
            {
                foreach (var identityFile in identityFiles)
                {
                    if (!File.Exists(identityFile))
                    {
                        continue;
                    }

                    try
                    {
                        string contents = File.ReadAllText(identityFile);
                        (SshKeyData identityFilePublicKey, bool isEncrypted) = PrivateKeyParser.ParsePublicKey(contents.AsMemory());
                        if (isEncrypted)
                        {
                            continue;
                        }
                        if (identityFilePublicKey.Equals(publicKey))
                        {
                            PrivateKey privateKey = PrivateKeyParser.ParsePrivateKey(contents.AsMemory(), () => "");
                            return (null, privateKey);
                        }
                    }
                    catch
                    { }
                }
            }

            bool connectedToSshAgent = false;
            int agentKeysChecked = 0;
            if (sshAgentCredential is not null)
            {
                string? address = sshAgentCredential.Address ?? SshAgent.DefaultAddress;
                if (address is not null)
                {
                    SshAgent? sshAgent = null;
                    try
                    {
                        sshAgent = new SshAgent(address, sequencePool);
                        await sshAgent.ConnectAsync(ct).ConfigureAwait(false);
                        connectedToSshAgent = true;
                    }
                    catch
                    {
                        sshAgent?.Dispose();
                        sshAgent = null;
                    }
                    if (sshAgent is not null)
                    {
                        List<SshAgent.Identity> keys = await sshAgent.RequestIdentitiesAsync(ct).ConfigureAwait(false);

                        foreach (var key in keys)
                        {
                            agentKeysChecked++;
                            if (key.PublicKey.Equals(publicKey))
                            {
                                PrivateKey privateKey = new SshAgentPrivateKey(sshAgent, key.PublicKey);
                                return (sshAgent, privateKey);
                            }
                        }
                    }
                }
            }

            logger.CertificateFileKeyNotFound(credentialFilePath, identityFiles?.Count ?? 0, connectedToSshAgent ? agentKeysChecked : null);
            return (null, null);
        }

        private static bool TryLoadCertificate(string path, ILogger<SshClient> logger, out SshKeyData certificate, out SshKeyData publicKey)
        {
            try
            {
                (certificate, publicKey) = ClientCertificateParser.ParseClientCertificateFile(path);
                if (certificate.IsDefault)
                {
                    logger.ClientCertificateNotFound(path);
                    return false;
                }
                return true;
            }
            catch (Exception error)
            {
                (certificate, publicKey) = (default, default);
                logger.ClientCertificateCanNotLoad(path, error);
                return false;
            }
        }

        public static async Task<AuthResult> TryAuthenticate(CertificateCredential credential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            if (!TryLoadCertificate(credential.Path, logger, out SshKeyData certificate, out SshKeyData publicKey))
            {
                return AuthResult.Skipped;
            }

            string keyIdentifier = credential.PrivateKey.Identifier;
            PrivateKeyCredential.Key key;
            try
            {
                key = await credential.PrivateKey.LoadKeyAsync(ct).ConfigureAwait(false);
            }
            catch (Exception error)
            {
                logger.PrivateKeyCanNotLoad(keyIdentifier, error);
                return AuthResult.Skipped;
            }

            using (key.PrivateKey)
            {
                if (key.PrivateKey is null)
                {
                    logger.PrivateKeyNotFound(keyIdentifier);
                    return AuthResult.Skipped;
                }

                if (!key.PrivateKey.PublicKey.Equals(publicKey))
                {
                    logger.ClientCertificatePrivateKeyMismatch(credential.Path, keyIdentifier);
                    return AuthResult.Skipped;
                }

                return await PublicKeyAuth.DoAuthAsync(credential.Path, key.PrivateKey, certificate, key.QueryKey, context, context.SupportedAcceptedPublicKeyAlgorithms, connectionInfo, logger, ct).ConfigureAwait(false);
            }
        }
    }
}