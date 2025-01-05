// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

static class ConnectService
{
    private static Connect _defaultConnect = new TcpConnect();

    public static async ValueTask<Stream> ConnectAsync(Proxy? proxy, ConnectContext context, CancellationToken cancellationToken)
    {
        Connect connect = _defaultConnect;
        if (proxy is null)
        {
            context.LogConnect(null);

            return await connect.ConnectAsync(context, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            ConnectContext proxyContext = context.CreateProxyContext(proxy);

            proxyContext.LogConnect(proxy.Uris);

            Stream stream = await connect.ConnectAsync(proxyContext, cancellationToken).ConfigureAwait(false);
            try
            {
                return await proxy.ConnectAsync(stream, context, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                stream.Dispose();

                throw;
            }
        }
    }
}
