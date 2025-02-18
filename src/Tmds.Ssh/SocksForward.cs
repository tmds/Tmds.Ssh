// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

public sealed class SocksForward : IDisposable
{
    private readonly LocalForwardServer<SocksForward> _forwarder;

    internal SocksForward(ILogger<SocksForward> logger)
    {
        _forwarder = new(logger);
    }

    internal ValueTask StartAsync(SshSession session, EndPoint bindEP, CancellationToken cancellationToken)
        => _forwarder.StartSocksForwardAsync(session, bindEP, cancellationToken);

    public EndPoint LocalEndPoint
        => _forwarder.LocalEndPoint;

    public CancellationToken Stopped
        => _forwarder.Stopped;

    public void ThrowIfStopped()
        => _forwarder.ThrowIfStopped();

    public void Dispose()
        => _forwarder.Dispose();
}