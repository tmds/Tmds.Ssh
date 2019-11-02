// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    // This class gathers settings for SshClient in a separate object.
    public sealed class SshClientSettings
    {
        public SshClientSettings(string userName, string host, Credential? credential = null)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentNullException(nameof(userName));
            }
            if (string.IsNullOrEmpty(host))
            {
                throw new ArgumentNullException(nameof(host));
            }

            UserName = userName;
            Host = host;

            if (credential != null)
            {
                Credentials.Add(credential);
            }
        }

        public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);
        public string UserName { get; }
        public string Host { get; }
        public int Port { get; set; } = 22;
        public List<Credential> Credentials { get; } = new List<Credential>();
        public HostKeyVerification HostKeyVerification { get; set; } = HostKeyVerification.TrustAll;

        // MAYDO: add property for default window size.

        // Internal.
        internal List<Name> KeyExchangeAlgorithms { get; } = new List<Name>() { AlgorithmNames.EcdhSha2Nistp256 };
        internal List<Name> ServerHostKeyAlgorithms { get; } = new List<Name>() { AlgorithmNames.SshRsa };
        internal List<Name> EncryptionAlgorithmsClientToServer { get; } = new List<Name>() { AlgorithmNames.Aes256Cbc };
        internal List<Name> EncryptionAlgorithmsServerToClient { get; } = new List<Name>() { AlgorithmNames.Aes256Cbc };
        internal List<Name> MacAlgorithmsClientToServer { get; } = new List<Name>() { AlgorithmNames.HMacSha2_256 };
        internal List<Name> MacAlgorithmsServerToClient { get; } = new List<Name>() { AlgorithmNames.HMacSha2_256 };
        internal List<Name> CompressionAlgorithmsClientToServer { get; } = new List<Name>() { AlgorithmNames.None };
        internal List<Name> CompressionAlgorithmsServerToClient { get; } = new List<Name>() { AlgorithmNames.None };
        internal List<Name> LanguagesClientToServer { get; } = new List<Name>();
        internal List<Name> LanguagesServerToClient { get; } = new List<Name>();

        // For testing:
        internal delegate Task<SshConnection> EstablishConnectionAsyncDelegate(ILogger logger, SequencePool sequencePool, SshClientSettings settings, CancellationToken ct);
        internal EstablishConnectionAsyncDelegate EstablishConnectionAsync = SshClient.EstablishConnectionAsync;
        internal ExchangeProtocolVersionAsyncDelegate ExchangeProtocolVersionAsync = ProtocolVersionExchange.Default;
        internal ExchangeKeysAsyncDelegate ExchangeKeysAsync = KeyExchange.Default;
        internal AuthenticateUserAsyncDelegate AuthenticateUserAsync = UserAuthentication.Default;
        internal bool NoProtocolVersionExchange = false;
        internal bool NoKeyExchange = false;
        internal bool NoUserAuthentication = false;
    }
}
