// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

/// <summary>
/// Controls remote port forwarding to a local endpoint.
/// </summary>
public sealed class RemoteForward : IDisposable
{
    private readonly RemoteForwardServer<RemoteForward> _forwarder;

    internal RemoteForward(ILogger<RemoteForward> logger)
    {
        _forwarder = new(logger);
    }

    internal ValueTask StartAsync(SshSession session, RemoteEndPoint bindEP, EndPoint localEndPoint, CancellationToken cancellationToken)
        => _forwarder.StartDirectForwardAsync(session, bindEP, localEndPoint, cancellationToken);

    /// <summary>
    /// Gets the remote endpoint being forwarded from.
    /// </summary>
    public RemoteEndPoint ListenEndPoint
        => _forwarder.RemoteEndPoint;

    /// <summary>
    /// Gets a token canceled when forwarding stops.
    /// </summary>
    public CancellationToken Stopped
        => _forwarder.Stopped;

    /// <summary>
    /// Throws if the forward has stopped.
    /// </summary>
    public void ThrowIfStopped()
        => _forwarder.ThrowIfStopped();

    /// <summary>
    /// Stops forwarding and releases resources.
    /// </summary>
    public void Dispose()
        => _forwarder.Dispose();
}