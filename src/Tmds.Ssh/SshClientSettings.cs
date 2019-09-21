// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    // This class gathers settings for SshClient in a separate object.
    public sealed class SshClientSettings
    {
        public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);
        public string Host { get; set; }
        public int Port { get; set; }

        // For testing:
        internal delegate Task<SshConnection> EstablishConnectionAsyncDelegate(ILogger logger, SequencePool sequencePool, SshClientSettings settings, CancellationToken ct);
        internal EstablishConnectionAsyncDelegate EstablishConnectionAsync = SshClient.EstablishConnectionAsync;
        internal delegate Task SetupConnectionAsyncDelegate(SshConnection sshConnection, ILogger logger, SshClientSettings settings, CancellationToken token);
        internal SetupConnectionAsyncDelegate SetupConnectionAsync = SshClient.SetupConnectionAsync;
        internal static readonly SetupConnectionAsyncDelegate NoSetup = async (_1, _2, _3, _4) => {};
    }
}
