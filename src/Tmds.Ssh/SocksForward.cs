// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

public sealed class SocksForward : IDisposable
{
    private readonly ForwardServer<SocksForward> _forwarder;

    internal SocksForward(ILogger<SocksForward> logger)
    {
        _forwarder = new(logger);
    }

    internal void Start(SshSession session, EndPoint bindEP)
        => _forwarder.StartSocksForward(session, bindEP);

    public EndPoint LocalEndPoint
        => _forwarder.LocalEndPoint;

    public CancellationToken ForwardStopped
        => _forwarder.ForwardStopped;

    public void ThrowIfStopped()
        => _forwarder.ThrowIfStopped();

    public void Dispose()
        => _forwarder.Dispose();
}