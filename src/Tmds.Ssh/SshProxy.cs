// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class SshProxy : Proxy
{
    private readonly SshClientSettings _settings;

    public SshProxy(SshClientSettings settings)
        : base(new UriBuilder("ssh", settings.HostName, settings.Port, null).Uri)
    {
        _settings = settings;
    }

    protected override async Task<Stream> ConnectCoreAsync(Stream stream, ConnectContext context, CancellationToken ct)
    {
        var sshClient = new SshClient(_settings, context.LoggerFactory);
        try
        {
            await sshClient.ConnectAsync(stream, ct);

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