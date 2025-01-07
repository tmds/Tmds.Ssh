// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class SshProxy : Proxy
{
    private readonly SshClientSettings _settings;
    private readonly ConnectEndPoint _endPoint;
    private readonly Uri _uri;

    public SshProxy(SshClientSettings settings)
    {
        _settings = settings;
        _endPoint = new ConnectEndPoint(_settings.HostName, _settings.Port);
        _uri = new UriBuilder("ssh", settings.HostName, settings.Port, null).Uri;
    }

    internal protected override async ValueTask<Stream> ConnectToProxyAndForward(ConnectCallback connect, ConnectContext context, CancellationToken ct)
    {
        ProxyConnectContext proxyContext = context.CreateProxyContext(_endPoint, _uri);
        Stream stream = await connect(proxyContext, ct);

        proxyContext.LogForward(context);
        return await ForwardAsync(stream, proxyContext, context.EndPoint, ct);
    }

    private async Task<Stream> ForwardAsync(Stream stream, ProxyConnectContext proxyContext, ConnectEndPoint target, CancellationToken ct)
    {
        var sshClient = new SshClient(_settings, proxyContext.LoggerFactory);
        try
        {
            await sshClient.ConnectAsync(proxyContext, stream, ct);

            SshDataStream dataStream = await sshClient.OpenTcpConnectionAsync(target.Host, target.Port, ct);

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