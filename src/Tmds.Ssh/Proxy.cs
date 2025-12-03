// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Base class for SSH connection proxies.
/// </summary>
public abstract class Proxy
{
    internal abstract ValueTask<Stream> ConnectToProxyAndForward(ConnectCallback connect, ConnectContext context, CancellationToken ct);

    /// <summary>
    /// Chains multiple proxies.
    /// </summary>
    /// <param name="proxies">The <see cref="Proxy"/> instances to chain.</param>
    /// <returns>A proxy that chains the specified proxies.</returns>
    public static Proxy? Chain(params Proxy[] proxies)
    {
        ArgumentNullException.ThrowIfNull(proxies);

        return proxies.Length switch
        {
            0 => null,
            1 => proxies[0],
            _ => new ProxyChain(proxies)
        };
    }

    sealed class ProxyChain : Proxy
    {
        private readonly Proxy[] _proxies;

        public ProxyChain(Proxy[] proxies)
        {
            _proxies = proxies;
        }

        internal override async ValueTask<Stream> ConnectToProxyAndForward(ConnectCallback connect, ConnectContext context, CancellationToken ct)
        {
            foreach (var proxy in _proxies)
            {
                connect = ConnectThroughProxy(connect, proxy);
            }

            return await connect(context, ct);
        }

        private ConnectCallback ConnectThroughProxy(ConnectCallback connect, Proxy proxy) =>
            (ConnectContext context, CancellationToken cancellationToken) => proxy.ConnectToProxyAndForward(connect, context, cancellationToken);
    }
}