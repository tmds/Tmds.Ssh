// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public class Proxy
{
    private readonly Proxy[] _children;

    internal ConnectEndPoint EndPoint { get; }
    internal Uri[] Uris { get; }

    protected Proxy(Uri uri, ConnectEndPoint? endPoint = null)
    {
        _children = [];
        Uris = [ uri ];
        EndPoint = endPoint ?? new ConnectEndPoint(uri.Host, uri.Port);
    }

    private Proxy(params Proxy[] proxies)
    {
        if (proxies.Length < 2)
        {
            throw new ArgumentOutOfRangeException();
        }

        int count = 0;
        foreach (var proxy in proxies)
        {
            ArgumentNullException.ThrowIfNull(proxy);
            count += proxy.Uris.Length;
        }

        Uris = new Uri[count];
        _children = new Proxy[count];

        int offset = 0;
        foreach (var proxy in proxies)
        {
            if (proxy.Uris.Length == 1)
            {
                _children[offset] = proxy;
                Uris[offset] = proxy.Uris[0];
            }
            else
            {
                proxy.Uris.AsSpan().CopyTo(Uris.AsSpan(offset));
                proxy._children.AsSpan().CopyTo(_children.AsSpan(offset));
            }
            offset += proxy.Uris.Length;
        }

        EndPoint = _children[0].EndPoint;
    }

    internal Task<Stream> ConnectAsync(Stream stream, ConnectContext context, CancellationToken ct)
    {
        if (Uris.Length == 1)
        {
            context.LogProxyConnect(Uris[0]);
            return ConnectCoreAsync(stream, context, ct);
        }
        else
        {
            return ConnectWithProxies(stream, _children, context, ct);
        }
    }

    private async Task<Stream> ConnectWithProxies(Stream stream, Proxy[] proxies, ConnectContext context, CancellationToken ct)
    {
        for (int i = 0; i < proxies.Length - 1; i++)
        {
            stream = await proxies[i].ConnectAsync(stream, context.CreateProxyContext(proxies[i + 1]), ct);
        }
        return await proxies[proxies.Length - 1].ConnectAsync(stream, context, ct);
    }

    protected virtual Task<Stream> ConnectCoreAsync(Stream stream, ConnectContext context, CancellationToken ct)
    {
        throw new InvalidOperationException();
    }

    public static Proxy? Chain(params Proxy[] proxies)
    {
        ArgumentNullException.ThrowIfNull(proxies);

        return proxies.Length switch
        {
            0 => null,
            1 => proxies[0],
            _ => new Proxy(proxies)
        };
    }
}