// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    public sealed class SshConnection : IDisposable
    {
        private readonly SshConnectionSettings _settings;
        private readonly ILogger _logger;

        public SshConnection(SshConnectionSettings settings, ILogger logger = null)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _logger = logger;
        }

        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            // TODO: SshConnectionSettings needs an upper bound time for this method (e.g. SshConnectionSettings.ConnectTimeout)
        }

        // This method is for doing a clean shutdown which may involve sending some messages over the wire.
        public async Task DisconnectAsync(CancellationToken cancellationToken)
        {
            // TODO: SshConnectionSettings needs an upper bound time for this method (e.g. SshConnectionSettings.DisconnectTimeout)

            // In a finally block, this method calls Dispose.
        }

        // This method will just cut the connection.
        public void Dispose()
        {
        }
    }
}
