using System.Net;

namespace Tmds.Ssh;

public class RemoteEndPoint
{
    private protected RemoteEndPoint()
    { }
}

sealed class RemoteDnsEndPoint : RemoteEndPoint
{
    public string Host { get; }
    public int Port { get; }
    private string? _toString;

    public RemoteDnsEndPoint(string host, int port)
    {
        ArgumentNullException.ThrowIfNull(host);
        if (port < 0 || port > 0xffff)
        {
            throw new ArgumentException(nameof(port));
        }

        Host = host;
        Port = port;
    }

    public override string ToString()
        => (_toString ??= $"{Host}:{Port}");
}

sealed class RemoteIPEndPoint : RemoteEndPoint
{
    public IPAddress Address { get; }
    public int Port { get; }
    private string? _toString;

    public RemoteIPEndPoint(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (port < 0 || port > 0xffff)
        {
            throw new ArgumentException(nameof(port));
        }

        Address = address;
        Port = port;
    }

    public override string ToString()
        => (_toString ??= $"{Address}:{Port}");
}

sealed class RemoteUnixEndPoint : RemoteEndPoint
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