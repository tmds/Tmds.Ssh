// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    internal delegate Task AuthenticateUserAsyncDelegate(SshConnection connection, ILogger logger, SshClientSettings settings, CancellationToken token);

    // Authentication Protocol: https://tools.ietf.org/html/rfc4252.
    sealed class UserAuthentication
    {
        public static readonly AuthenticateUserAsyncDelegate Default = PerformDefaultAuthentication;

        private static Task PerformDefaultAuthentication(SshConnection connection, ILogger logger, SshClientSettings settings, CancellationToken token)
        {
            // TODO
            return Task.CompletedTask;
        }
    }
}