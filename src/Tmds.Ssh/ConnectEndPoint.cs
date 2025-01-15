// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

sealed class ConnectEndPoint
{
    private string? _toString;

    public ConnectEndPoint(string host, int port)
    {
        ArgumentValidation.ValidateHost(host);
        ArgumentValidation.ValidatePort(port, allowZero: false);

        Host = host;
        Port = port;
    }

    public string Host { get; }

    public int Port { get; }

    public override string ToString()
        => (_toString ??= $"{Host}:{Port}");
}