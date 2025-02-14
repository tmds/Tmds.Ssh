// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Net.Sockets;

namespace Tmds.Ssh;

public class RemoteEndPoint
{
    private protected RemoteEndPoint()
    { }
}

public sealed class RemoteHostEndPoint : RemoteEndPoint
{
    public string Host { get; }
    public int Port { get; }
    private string? _toString;

    public RemoteHostEndPoint(string host, int port)
    {
        ArgumentValidation.ValidateHost(host);
        ArgumentValidation.ValidatePort(port, allowZero: false);

        Host = host;
        Port = port;
    }

    public override string ToString()
        => _toString ??= Host.Contains(':') ? $"[{Host}]:{Port}" : $"{Host}:{Port}";
}

public sealed class RemoteIPEndPoint : RemoteEndPoint
{
    public IPAddress Address { get; }
    public int Port { get; }
    private string? _toString;

    public RemoteIPEndPoint(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentValidation.ValidatePort(port, allowZero: false);

        Address = address;
        Port = port;
    }

    public override string ToString()
        => _toString ??= Address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Address}]:{Port}" : $"{Address}:{Port}";
}

public sealed class RemoteUnixEndPoint : RemoteEndPoint
{
    public string Path { get; }

    public RemoteUnixEndPoint(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        Path = path;
    }

    public override string ToString()
        => Path;
}

public sealed class RemoteIPListenEndPoint : RemoteEndPoint
{
    public string Address { get; }
    public int Port { get; }
    private string? _toString;

    public RemoteIPListenEndPoint(string address, int port)
    {
        ArgumentValidation.ValidateIPListenAddress(address);
        ArgumentValidation.ValidatePort(port, allowZero: false);

        Address = address;
        Port = port;
    }

    public override string ToString()
        => _toString ??= Address.Contains(':') ? $"[{Address}]:{Port}" : $"{Address}:{Port}";
}