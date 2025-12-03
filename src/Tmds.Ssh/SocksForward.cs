// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

/// <summary>
/// SOCKS proxy server that forwards connections through the SSH server.
/// </summary>
public sealed class SocksForward : IDisposable
{
    private readonly LocalForwardServer<SocksForward> _forwarder;

    internal SocksForward(ILogger<SocksForward> logger)
    {
        _forwarder = new(logger);
    }

    internal ValueTask StartAsync(SshSession session, EndPoint bindEP, CancellationToken cancellationToken)
        => _forwarder.StartSocksForwardAsync(session, bindEP, cancellationToken);

    /// <summary>
    /// Gets the local endpoint the SOCKS server listens on.
    /// </summary>
    public EndPoint ListenEndPoint
        => _forwarder.LocalEndPoint;

    /// <summary>
    /// Gets a token canceled when the SOCKS server stops.
    /// </summary>
    public CancellationToken Stopped
        => _forwarder.Stopped;

    /// <summary>
    /// Throws if the SOCKS server has stopped.
    /// </summary>
    public void ThrowIfStopped()
        => _forwarder.ThrowIfStopped();

    /// <summary>
    /// Stops the SOCKS server and releases resources.
    /// </summary>
    public void Dispose()
        => _forwarder.Dispose();
}