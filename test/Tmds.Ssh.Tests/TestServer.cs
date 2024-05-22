using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh.Managed.Tests;

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

    public async Task<SshClient> CreateClientAsync(Action<ManagedSshClientSettings>? configure = null)
    {
        IPEndPoint ipEndPoint = (_serverSocket.LocalEndPoint as IPEndPoint)!;

        var clientSettings = new SshClientSettings($"user@{ipEndPoint.Address}:{ipEndPoint.Port}");

        ManagedSshClientSettings managedSettings = ManagedSshClient.CreateManagedSshSettings(clientSettings);

        configure?.Invoke(managedSettings);

        var client = new SshClient(managedSettings);

        await client.ConnectAsync();

        return client;
    }

    private async Task HandleClientAsync()
    {
        Socket clientSocket = await _serverSocket.AcceptAsync().ConfigureAwait(false);
        using SocketSshConnection socketSshConnection = new SocketSshConnection(NullLogger.Instance, new SequencePool(), clientSocket);
        await _handler(socketSshConnection);
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
