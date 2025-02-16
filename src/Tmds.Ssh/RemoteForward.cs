// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

public sealed class RemoteForward : IDisposable
{
    private readonly RemoteForwardServer<RemoteForward> _forwarder;

    internal RemoteForward(ILogger<RemoteForward> logger)
    {
        _forwarder = new(logger);
    }

    internal ValueTask StartAsync(SshSession session, RemoteEndPoint bindEP, EndPoint localEndPoint, CancellationToken cancellationToken)
        => _forwarder.StartDirectForwardAsync(session, bindEP, localEndPoint, cancellationToken);

    public RemoteEndPoint RemoteEndPoint
        => _forwarder.RemoteEndPoint;

    public CancellationToken Stopped
        => _forwarder.Stopped;

    public void ThrowIfStopped()
        => _forwarder.ThrowIfStopped();

    public void Dispose()
        => _forwarder.Dispose();
}