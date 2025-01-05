// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class ConnectEndPoint
{
    private string? _toString;

    public ConnectEndPoint(string host, int port)
    {
        ArgumentNullException.ThrowIfNull(host);
        if (port < 0 || port > 0xffff)
        {
            throw new ArgumentException(nameof(port));
        }

        Host = host;
        Port = port;
    }

    public string Host { get; }

    public int Port { get; }

    public override string ToString()
        => (_toString ??= $"{Host}:{Port}");
}