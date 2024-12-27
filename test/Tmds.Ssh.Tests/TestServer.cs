using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh.Tests;

delegate Task SshConnectionHandler(SshConnection connection);

sealed class TestServer : IAsyncDisposable
{
    private readonly Socket _serverSocket;
    private readonly Task _handleClientTask;
    private readonly SshConnectionHandler _handler;

    public TestServer(SshConnectionHandler handler)
    {
        _handler = handler;
        _serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
        _serverSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _serverSocket.Listen(1);
        _handleClientTask = HandleClientAsync();
    }

    public async Task<SshClient> CreateClientAsync(Action<SshClientSettings>? configure = null)
    {
        IPEndPoint ipEndPoint = (_serverSocket.LocalEndPoint as IPEndPoint)!;

        var settings = new SshClientSettings($"user@{ipEndPoint.Address}:{ipEndPoint.Port}");

        configure?.Invoke(settings);

        var client = new SshClient(settings);

        await client.ConnectAsync();

        return client;
    }

    private async Task HandleClientAsync()
    {
        ILogger<SshClient> logger = new NullLoggerFactory().CreateLogger<SshClient>();
        Socket clientSocket = await _serverSocket.AcceptAsync().ConfigureAwait(false);
        using StreamSshConnection sshConnection = new StreamSshConnection(logger, new SequencePool(), new NetworkStream(clientSocket, ownsSocket: true));
        await _handler(sshConnection);
    }

    public void Dispose()
    {
        _serverSocket.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        _serverSocket.Dispose();
        await _handleClientTask;
    }
}
