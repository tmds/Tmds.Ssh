// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    internal delegate Task ExchangeKeysAsyncDelegate(SshConnection sshConnection, Sequence? remoteInitPacket, ILogger logger, SshClientSettings settings, CancellationToken token);
    sealed class KeyExchange
    {
        public static readonly ExchangeKeysAsyncDelegate Default = PerformDefaultExchange;

        private static Task PerformDefaultExchange(SshConnection sshConnection, Sequence? remoteInitPacket, ILogger logger, SshClientSettings settings, CancellationToken token)
        {
            // Key Exchange: https://tools.ietf.org/html/rfc4253#section-7.

            // TODO: validate remoteInitPacket!

            // Configure sshConnection for encryption.
            return Task.CompletedTask;
        }

        public static Sequence CreateKeyExchangeInitMessage(SequencePool sequencePool, ILogger logger, SshClientSettings settings)
        {
            var sequence = sequencePool.RentSequence();
            // TODO
            return sequence;
        }
    }
}