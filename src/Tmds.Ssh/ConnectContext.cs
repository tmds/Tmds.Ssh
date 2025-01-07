// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

class ConnectContext
{
    internal ConnectContext? Parent { get; }

    public ILoggerFactory LoggerFactory { get; }

    public ConnectContext DestinationContext => Parent?.DestinationContext ?? Parent ?? this;

    public ConnectEndPoint EndPoint { get; }

    public ConnectEndPoint DestinationEndPoint => DestinationContext.EndPoint;

    public bool TcpKeepAlive { get; protected set; }

    internal ConnectContext(ConnectEndPoint endPoint, ILoggerFactory loggerFactory)
    {
        EndPoint = endPoint;
        LoggerFactory = loggerFactory;
    }

    internal ConnectContext(ConnectEndPoint endPoint, ConnectContext parent)
    {
        EndPoint = endPoint;
        Parent = parent;
        TcpKeepAlive = parent.TcpKeepAlive;
        LoggerFactory = parent.LoggerFactory;
    }

    internal ProxyConnectContext CreateProxyContext(ConnectEndPoint proxyEndPoint, Uri proxyUri)
    {
        return new ProxyConnectContext(this, proxyEndPoint, proxyUri);
    }

    internal virtual void SetHostIPAddress(IPAddress address)
    { }

    private protected virtual void LogConnect(ConnectContext context)
    {
        Parent?.LogConnect(context);
    }

    protected virtual void LogForward(ProxyConnectContext proxyContext, ConnectContext targetContext)
    {
        Parent?.LogForward(proxyContext, targetContext);
    }

    internal void LogConnect()
        => LogConnect(this);

    internal IEnumerable<Uri> ProxyUris
    {
        get
        {
            if (this is ProxyConnectContext proxyContext)
            {
                yield return proxyContext.ProxyUri;
            }
            if (Parent is not null)
            {
                foreach (var uri in Parent.ProxyUris)
                {
                    yield return uri;
                }
            }
        }
    }
}

sealed class ProxyConnectContext : ConnectContext
{
    public Uri ProxyUri { get; }

    internal ProxyConnectContext(ConnectContext parent, ConnectEndPoint proxyEndPoint, Uri proxyUri) :
        base(proxyEndPoint, parent)
    {
        ProxyUri = proxyUri;
    }

    public void LogForward(ConnectContext target)
    {
        LogForward(this, target);
    }

    internal override void SetHostIPAddress(IPAddress address)
    { }
}