// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

/// <summary>
/// Controls local port forwarding to a remote endpoint.
/// </summary>
public sealed class LocalForward : IDisposable
{
    private readonly LocalForwardServer<LocalForward> _forwarder;

    internal LocalForward(ILogger<LocalForward> logger)
    {
        _forwarder = new(logger);
    }

    internal ValueTask StartAsync(SshSession session, EndPoint bindEP, RemoteEndPoint remoteEndPoint, CancellationToken cancellationToken)
        => _forwarder.StartDirectForwardAsync(session, bindEP, remoteEndPoint, cancellationToken);

    /// <summary>
    /// Gets the local endpoint being forwarded from.
    /// </summary>
    public EndPoint ListenEndPoint
        => _forwarder.LocalEndPoint;

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