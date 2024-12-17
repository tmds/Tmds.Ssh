using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

public sealed class DirectForward : IDisposable
{
    private readonly ForwardServer<DirectForward> _forwarder;

    internal DirectForward(ILogger<DirectForward> logger)
    {
        _forwarder = new(logger);
    }

    internal void Start(SshSession session, EndPoint bindEP, RemoteEndPoint remoteEndPoint)
        => _forwarder.StartDirectForward(session, bindEP, remoteEndPoint);

    public EndPoint LocalEndPoint
        => _forwarder.LocalEndPoint;

    public CancellationToken ForwardStopped
        => _forwarder.ForwardStopped;

    public void ThrowIfStopped()
        => _forwarder.ThrowIfStopped();

    public void Dispose()
        => _forwarder.Dispose();
}