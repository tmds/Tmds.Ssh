// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;

namespace Tmds.Ssh;

/// <summary>
/// Proxy through an SSH server.
/// </summary>
public sealed class SshProxy : Proxy
{
    private readonly SshClientSettings? _settings;
    private readonly string? _destination;
    private readonly SshConfigSettings? _configSettings;
    private readonly ConnectEndPoint _endPoint;
    private readonly Uri _uri;

    /// <summary>
    /// Creates an SSH proxy with the specified settings.
    /// </summary>
    /// <param name="settings"><see cref="SshClientSettings"/> for the proxy connection.</param>
    public SshProxy(SshClientSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.Validate();

        _settings = settings;
        _endPoint = new ConnectEndPoint(_settings.HostName, _settings.Port);
        _uri = new UriBuilder("ssh", settings.HostName, settings.Port).Uri;
    }

    /// <summary>
    /// Creates an SSH proxy with a destination and config settings.
    /// </summary>
    /// <param name="destination">SSH destination (e.g., user@host or host).</param>
    /// <param name="configSettings"><see cref="SshConfigSettings"/> for the connection.</param>
    public SshProxy(string destination, SshConfigSettings configSettings)
        : this(destination)
    {
        ArgumentNullException.ThrowIfNull(configSettings);

        _configSettings = configSettings;
    }

    /// <summary>
    /// Creates an SSH proxy with a destination.
    /// </summary>
    /// <param name="destination">SSH destination (e.g., user@host or host).</param>
    public SshProxy(string destination)
    {
        ArgumentException.ThrowIfNullOrEmpty(destination);

        _destination = destination;

        (string? username, string host, int? port) = SshClientSettings.ParseDestination(destination);
        port ??= 22;
        _endPoint = new ConnectEndPoint(host, port.Value);
        _uri = new UriBuilder("ssh", host, port.Value).Uri;
    }

    internal override async ValueTask<Stream> ConnectToProxyAndForward(ConnectCallback connect, ConnectContext context, CancellationToken ct)
    {
        ProxyConnectContext proxyContext = context.CreateProxyContext(_endPoint, _uri);

        SshClient sshClient = CreateSshClient(context);
        try
        {
            await sshClient.ConnectAsync(connect, proxyContext, ct);

            proxyContext.LogForward(context);
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

    private SshClient CreateSshClient(ConnectContext context)
    {
        if (_settings is not null)
        {
            return new SshClient(_settings, context.LoggerFactory);
        }

        Debug.Assert(_destination is not null);

        if (_configSettings is not null)
        {
            return new SshClient(_destination, _configSettings!, context.LoggerFactory);
        }

        // Use settings based on the destination SshSettings.
        SshConnectContext? sshConnectContext = context.DestinationContext as SshConnectContext;
        Debug.Assert(sshConnectContext is not null);
        if (sshConnectContext is null)
        {
            return new SshClient(new SshClientSettings(_destination), context.LoggerFactory);
        }
        else
        {
            return sshConnectContext.CreateProxyClientForDestination(_destination, context.LoggerFactory);
        }
    }
}