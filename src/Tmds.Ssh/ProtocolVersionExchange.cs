// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    internal delegate Task ExchangeProtocolVersionAsyncDelegate(SshConnection sshConnection, ILogger logger, SshClientSettings settings, CancellationToken token);
    sealed class ProtocolVersionExchange
    {
        public static readonly ExchangeProtocolVersionAsyncDelegate Default = PerformDefaultExchange;

        private static Task PerformDefaultExchange(SshConnection sshConnection, ILogger logger, SshClientSettings settings, CancellationToken token)
        {
            // Protocol Version Exchange: https://tools.ietf.org/html/rfc4253#section-4.2.
            
            return Task.CompletedTask;
        }
    }
}