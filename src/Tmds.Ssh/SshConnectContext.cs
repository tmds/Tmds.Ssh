// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;

namespace Tmds.Ssh;

sealed class SshConnectContext : ConnectContext
{
    private readonly SshClientSettings _settings;
    private readonly SshConnectionInfo _connectionInfo;
    private readonly SshLoggers _loggers;

    internal SshConnectContext(SshClientSettings settings, SshConnectionInfo connectionInfo, SshLoggers loggers) :
        base(new ConnectEndPoint(settings.HostName, settings.Port), loggers.Factory)
    {
        _settings = settings;
        _connectionInfo = connectionInfo;
        _loggers = loggers;
        TcpKeepAlive = settings.TcpKeepAlive;
    }

    internal override void SetHostIPAddress(IPAddress address)
    {
        _connectionInfo.IPAddress = address;
    }

    private protected override void LogConnect(ConnectContext context)
    {
        _loggers.SshClientLogger.HostConnect(context.EndPoint, context.DestinationEndPoint, context.ProxyUris);
    }

    protected override void LogForward(ProxyConnectContext proxyContext, ConnectContext targetContext)
    {
        _loggers.SshClientLogger.Proxy(proxyContext.ProxyUri, targetContext.EndPoint, targetContext.DestinationEndPoint);
    }
}