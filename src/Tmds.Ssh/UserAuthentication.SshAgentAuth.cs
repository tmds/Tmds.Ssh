// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    public sealed class SshAgentAuth
    {
        public static async Task<AuthResult> TryAuthenticate(SshAgentCredentials credential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger<SshClient> logger, CancellationToken ct)
        {
            string? endPoint = SshAgent.DefaultEndPoint;
            if (endPoint is null)
            {
                return AuthResult.None;
            }

            using var sshAgent = new SshAgent(endPoint, context.SequencePool);

            if (!await sshAgent.TryConnect(ct))
            {
                return AuthResult.None;
            }

            List<SshAgent.Identity> keys = await sshAgent.RequestIdentitiesAsync(ct);
            if (keys.Count == 0)
            {
                return AuthResult.None;
            }

            AuthResult rv = AuthResult.Skipped;

            foreach (var key in keys)
            {
                using var pk = new SshAgentPrivateKey(sshAgent, key.PublicKey);

                string keyIdentifier = $"ssh-agent:{key.Comment}";

                AuthResult result = await PublicKeyAuth.DoAuthAsync(keyIdentifier, pk, queryKey: true, context, context.AcceptedPublicKeyAlgorithms, connectionInfo, logger, ct).ConfigureAwait(false);

                if (result is AuthResult.Success or AuthResult.Partial or AuthResult.FailureMethodNotAllowed)
                {
                    return result;
                }

                Debug.Assert(result is AuthResult.Failure or AuthResult.Skipped);
                // Return Skipped if all skipped, otherwise return Failure.
                if (result == AuthResult.Failure)
                {
                    rv = AuthResult.Failure;
                }
            }

            return rv;
        }
    }
}