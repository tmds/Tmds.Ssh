// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class SshProxy : Proxy
{
    private readonly SshClientSettings? _settings;
    private readonly string? _destination;
    private readonly SshConfigSettings? _configSettings;
    private readonly ConnectEndPoint _endPoint;
    private readonly Uri _uri;

    public SshProxy(SshClientSettings settings)
    {
        _settings = settings;
        _endPoint = new ConnectEndPoint(_settings.HostName, _settings.Port);
        _uri = new UriBuilder("ssh", settings.HostName, settings.Port).Uri;
    }

    public SshProxy(string destination, SshConfigSettings configSettings)
    {
        ArgumentException.ThrowIfNullOrEmpty(destination);
        ArgumentNullException.ThrowIfNull(configSettings);

        _destination = destination;
        _configSettings = configSettings;

        (string? username, string host, int? port) = SshClientSettings.ParseDestination(destination);
        port ??= 22;
        _endPoint = new ConnectEndPoint(host, port.Value);
        _uri = new UriBuilder("ssh", host, port.Value).Uri;
    }

    internal protected override async ValueTask<Stream> ConnectToProxyAndForward(ConnectCallback connect, ConnectContext context, CancellationToken ct)
    {
        ProxyConnectContext proxyContext = context.CreateProxyContext(_endPoint, _uri);

        var sshClient = _settings is not null ? new SshClient(_settings, proxyContext.LoggerFactory)
                                              : new SshClient(_destination!, _configSettings!, proxyContext.LoggerFactory);
        try
        {
            await sshClient.ConnectAsync(connect, proxyContext, ct);

            proxyContext.LogForward(context);
            SshDataStream dataStream = await sshClient.OpenTcpConnectionAsync(context.EndPoint.Host, context.EndPoint.Port, ct);

            dataStream.StreamAborted.UnsafeRegister(o => ((SshClient)o!).Dispose(), sshClient);

            return dataStream;
        }
        catch
        {
            sshClient.Dispose();

            throw;
        }
    }
}