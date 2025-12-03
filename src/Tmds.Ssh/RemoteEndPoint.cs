// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Net.Sockets;

namespace Tmds.Ssh;

/// <summary>
/// Base class for remote endpoints.
/// </summary>
public class RemoteEndPoint
{
    private protected RemoteEndPoint()
    { }
}

/// <summary>
/// Remote endpoint specified by hostname and port.
/// </summary>
public sealed class RemoteHostEndPoint : RemoteEndPoint
{
    /// <summary>
    /// Gets the hostname.
    /// </summary>
    public string Host { get; }

    /// <summary>
    /// Gets the port.
    /// </summary>
    public int Port { get; }
    private string? _toString;

    /// <summary>
    /// Creates a remote host endpoint.
    /// </summary>
    /// <param name="host">The hostname.</param>
    /// <param name="port">The port.</param>
    public RemoteHostEndPoint(string host, int port)
    {
        ArgumentValidation.ValidateHost(host);
        ArgumentValidation.ValidatePort(port, allowZero: false);

        Host = host;
        Port = port;
    }

    /// <inheritdoc />
    public override string ToString()
        => _toString ??= Host.Contains(':') ? $"[{Host}]:{Port}" : $"{Host}:{Port}";
}

/// <summary>
/// Remote endpoint specified by IP address and port.
/// </summary>
public sealed class RemoteIPEndPoint : RemoteEndPoint
{
    /// <summary>
    /// Gets the IP address.
    /// </summary>
    public IPAddress Address { get; }

    /// <summary>
    /// Gets the port.
    /// </summary>
    public int Port { get; }
    private string? _toString;

    /// <summary>
    /// Creates a remote IP endpoint.
    /// </summary>
    /// <param name="address">The IP address.</param>
    /// <param name="port">The port.</param>
    public RemoteIPEndPoint(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentValidation.ValidatePort(port, allowZero: false);

        Address = address;
        Port = port;
    }

    /// <inheritdoc />
    public override string ToString()
        => _toString ??= Address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Address}]:{Port}" : $"{Address}:{Port}";
}

/// <summary>
/// Remote Unix domain socket endpoint.
/// </summary>
public sealed class RemoteUnixEndPoint : RemoteEndPoint
{
    /// <summary>
    /// Gets the Unix socket path.
    /// </summary>
    public string Path { get; }

    /// <summary>
    /// Creates a remote Unix endpoint.
    /// </summary>
    /// <param name="path">The Unix socket path.</param>
    public RemoteUnixEndPoint(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        Path = path;
    }

    /// <inheritdoc />
    public override string ToString()
        => Path;
}

/// <summary>
/// Remote listen endpoint for port forwarding.
/// </summary>
public sealed class RemoteIPListenEndPoint : RemoteEndPoint
{
    /// <summary>
    /// Gets the listen address.
    /// </summary>
    public string Address { get; }

    /// <summary>
    /// Gets the listen port (0 for auto-assigned).
    /// </summary>
    public int Port { get; }
    private string? _toString;

    /// <summary>
    /// Creates a remote listen endpoint.
    /// </summary>
    /// <param name="address">The listen address.</param>
    /// <param name="port">The listen port (0 for auto-assigned).</param>
    public RemoteIPListenEndPoint(string address, int port)
    {
        ArgumentValidation.ValidateIPListenAddress(address);
        ArgumentValidation.ValidatePort(port, allowZero: true);

        Address = address;
        Port = port;
    }

    /// <inheritdoc />
    public override string ToString()
        => _toString ??= Address.Contains(':') ? $"[{Address}]:{Port}" : $"{Address}:{Port}";
}