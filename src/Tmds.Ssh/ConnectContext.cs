// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

public class ConnectContext
{
    internal ConnectContext? Parent { get; }

    public ILoggerFactory LoggerFactory { get; }

    public ConnectContext DestinationContext => Parent ?? this;

    public ConnectEndPoint EndPoint { get; }

    public ConnectEndPoint DestinationEndPoint => DestinationContext.EndPoint;

    public bool TcpKeepAlive { get; protected set; }

    internal ConnectContext(ConnectEndPoint endPoint, ILoggerFactory loggerFactory)
    {
        EndPoint = endPoint;
        LoggerFactory = loggerFactory;
    }

    private ConnectContext(ConnectEndPoint endPoint, ConnectContext parent)
    {
        EndPoint = endPoint;
        Parent = parent;
        TcpKeepAlive = parent.TcpKeepAlive;
        LoggerFactory = parent.LoggerFactory;
    }

    internal ConnectContext CreateProxyContext(Proxy proxy)
    {
        return new ProxyConnectContext(this, proxy);
    }

    internal virtual void SetHostIPAddress(IPAddress address)
    { }

    private protected virtual void LogConnect(ConnectContext context, IEnumerable<Uri>? proxyUris)
    {
        Parent?.LogConnect(context, proxyUris);
    }

    protected virtual void LogProxyConnect(ConnectContext context, Uri proxyUri)
    {
        Parent?.LogProxyConnect(context, proxyUri);
    }

    internal void LogConnect(IEnumerable<Uri>? proxyUris)
        => LogConnect(this, proxyUris);

    internal void LogProxyConnect(Uri proxyUri)
        => LogProxyConnect(this, proxyUri);

    sealed class ProxyConnectContext : ConnectContext
    {
        internal ProxyConnectContext(ConnectContext parent, Proxy proxyConnect) :
            base(proxyConnect.EndPoint!, parent)
        { }

        internal override void SetHostIPAddress(IPAddress address)
        { }
    }
}