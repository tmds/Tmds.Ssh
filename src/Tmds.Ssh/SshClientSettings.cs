// This file is part of Tmds.Ssh which is released under LGPL-3.0.
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
        public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);
        public string? Host { get; set; }
        public int Port { get; set; } = 22;
        internal List<string> KeyAlgorithms { get; } = new List<string>();
        internal List<string> ServerHostKeyAlgorithms { get; } = new List<string>();
        internal List<string> EncryptionAlgorithmsClientToServer { get; } = new List<string>();
        internal List<string> EncryptionAlgorithmsServerToClient { get; } = new List<string>();
        internal List<string> MacAlgorithmsClientToServer { get; } = new List<string>();
        internal List<string> MacAlgorithmsServerToClient { get; } = new List<string>();
        internal List<string> CompressionAlgorithmsClientToServer { get; } = new List<string>();
        internal List<string> CompressionAlgorithmsServerToClient { get; } = new List<string>();
        internal List<string> LanguagesClientToServer { get; } = new List<string>();
        internal List<string> LanguagesServerToClient { get; } = new List<string>();

        // For testing:
        internal delegate Task<SshConnection> EstablishConnectionAsyncDelegate(ILogger logger, SequencePool sequencePool, SshClientSettings settings, CancellationToken ct);
        internal EstablishConnectionAsyncDelegate EstablishConnectionAsync = SshClient.EstablishConnectionAsync;
        internal delegate Task SetupConnectionAsyncDelegate(SshConnection sshConnection, ILogger logger, SshClientSettings settings, CancellationToken token);
        internal ExchangeProtocolVersionAsyncDelegate ExchangeProtocolVersionAsync = ProtocolVersionExchange.Default;
        internal ExchangeKeysAsyncDelegate ExchangeKeysAsync = KeyExchange.Default;
        internal AuthenticateUserAsyncDelegate AuthenticateUserAsync = UserAuthentication.Default;
        internal bool NoProtocolVersionExchange = false;
        internal bool NoKeyExchange = false;
        internal bool NoUserAuthentication = false;
    }
}
