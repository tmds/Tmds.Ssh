// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using static Tmds.Ssh.Interop;

namespace Tmds.Ssh
{
    public sealed partial class SshClient : IDisposable
    {
        enum CredentialAuthResult
        {
            Success,
            Error,

            Again,

            NextCredential
        }

        enum AuthStep
        {
            Initial,

            // Steps for PrivateKeyFileCredential.
            IdentityFileKeyImported,
            IdentityFilePubKeyAccepted
        }

        class AuthState
        {
            // Index in settings Credentials.
            public int CredentialIndex;

            public AuthStep Step;

            public SshKeyHandle? PublicKey;
            public SshKeyHandle? PrivateKey;

            public void Reset()
            {
                PublicKey?.Dispose();
                PrivateKey?.Dispose();

                Step = AuthStep.Initial;
                PublicKey = null;
                PrivateKey = null;
            }
        }

        static volatile List<Credential>? s_defaultCredentials;

        private static List<Credential> GetDefaultCredentials()
        {
            if (s_defaultCredentials == null)
            {
                List<Credential> credentials = new();
                string home = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments, Environment.SpecialFolderOption.DoNotVerify);
                credentials.Add(new PrivateKeyFileCredential(Path.Combine(home, ".ssh", "id_ed25519")));
                credentials.Add(new PrivateKeyFileCredential(Path.Combine(home, ".ssh", "id_ecdsa")));
                credentials.Add(new PrivateKeyFileCredential(Path.Combine(home, ".ssh", "id_rsa")));
                credentials.Add(new PrivateKeyFileCredential(Path.Combine(home, ".ssh", "id_dsa")));
                s_defaultCredentials = credentials;
            }
            return s_defaultCredentials;
        }

        private void Authenticate()
        {
            var credentials = _clientSettings.Credentials;
            if (credentials == null || credentials.Count == 0)
            {
                credentials = GetDefaultCredentials();
            }
            bool ignoreErrors = credentials.Count > 1;
            while (true)
            {
                int credentialIndex = _authState.CredentialIndex;
                if (credentialIndex >= credentials.Count)
                {
                    CompleteConnect(new SshSessionException("Client authentication failed."));
                    return;
                }
                Credential credential = credentials[credentialIndex];

                string? errorMessage = null;
                CredentialAuthResult result = credential switch
                {
                    PrivateKeyFileCredential ifc => Authenticate(ifc, ignoreErrors, out errorMessage),
                    _ => throw new IndexOutOfRangeException($"Unexpected credential type: {credential.GetType().FullName}")
                };

                if (result != CredentialAuthResult.Again)
                {
                    _authState.Reset();
                }

                if (result == CredentialAuthResult.Success)
                {
                    _state = SessionState.Connected;
                    CompleteConnect(null);
                }
                else if (result == CredentialAuthResult.Error)
                {
                    CompleteConnect(new SshSessionException(errorMessage ?? ssh_get_error(_ssh)));
                }
                else if (result == CredentialAuthResult.NextCredential)
                {
                    _authState.CredentialIndex = credentialIndex + 1;
                }
                else
                {
                    Debug.Assert(result == CredentialAuthResult.Again);
                    return;
                }
            }
        }

        private CredentialAuthResult Authenticate(PrivateKeyFileCredential credential, bool ignoreErrors, out string? errorMessage)
        {
            errorMessage = null;

            string privateKeyFile = credential.FileName;
            if (_authState.Step == AuthStep.Initial)
            {
                Debug.Assert(_authState.PublicKey == null);
                Debug.Assert(_authState.PrivateKey == null);

                string publicKeyFile = $"{privateKeyFile}.pub";

                int rv = ssh_pki_import_pubkey_file(publicKeyFile, out _authState.PublicKey);
                if (rv == SSH_ERROR)
                {
                    return CredentialAuthResult.NextCredential;
                }
                else if (rv == SSH_EOF) // File not found.
                {
                    // TODO: Read the private key and save the public key to file
                    if (!ignoreErrors)
                    {
                        errorMessage = $"Failed to read public key file: {publicKeyFile}.";
                        return CredentialAuthResult.Error;
                    }
                    return CredentialAuthResult.NextCredential;
                }
                Debug.Assert(rv == SSH_OK);
                _authState.Step = AuthStep.IdentityFileKeyImported;
            }

            if (_authState.Step == AuthStep.IdentityFileKeyImported)
            {
                AuthResult rv = ssh_userauth_try_publickey(_ssh, null, _authState.PublicKey!);
                if (rv == AuthResult.Error)
                {
                    return CredentialAuthResult.Error;
                }
                else if (rv == AuthResult.Again)
                {
                    return CredentialAuthResult.Again;
                }
                else if (rv != AuthResult.Success)
                {
                    return CredentialAuthResult.NextCredential;
                }
                _authState.Step = AuthStep.IdentityFilePubKeyAccepted;
            }

            Debug.Assert(_authState.Step == AuthStep.IdentityFilePubKeyAccepted);
            if (_authState.PrivateKey == null)
            {
                int rv = ssh_pki_import_privkey_file(privateKeyFile, null, out _authState.PrivateKey);
                if (rv == SSH_ERROR)
                {
                    if (!ignoreErrors)
                    {
                        errorMessage = $"Failed to read private key file: {privateKeyFile}.";
                        return CredentialAuthResult.Error;
                    }
                    return CredentialAuthResult.NextCredential;
                }
                else if (rv == SSH_EOF)
                {
                    if (!ignoreErrors)
                    {
                        errorMessage = $"Private key file is missing: {privateKeyFile}.";
                        return CredentialAuthResult.Error;
                    }
                    return CredentialAuthResult.NextCredential;
                }
                Debug.Assert(rv == SSH_OK);
            }

            {
                AuthResult rv = ssh_userauth_publickey(_ssh, null, _authState.PrivateKey!);
                if (rv == AuthResult.Success)
                {
                    return CredentialAuthResult.Success;
                }
                else if (rv == AuthResult.Again)
                {
                    return CredentialAuthResult.Again;
                }
                else if (rv == AuthResult.Error)
                {
                    return CredentialAuthResult.Error;
                }

                return CredentialAuthResult.NextCredential;
            }
        }
    }
}