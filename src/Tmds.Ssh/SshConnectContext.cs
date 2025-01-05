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

    private protected override void LogConnect(ConnectContext context, IEnumerable<Uri>? proxyUris)
    {
        _loggers.SshClientLogger.HostConnect(context.EndPoint, context.DestinationEndPoint, proxyUris ?? []);
    }

    protected override void LogProxyConnect(ConnectContext context, Uri proxyUri)
    {
        _loggers.SshClientLogger.Proxy(proxyUri, context.EndPoint, context.DestinationEndPoint);
    }
}