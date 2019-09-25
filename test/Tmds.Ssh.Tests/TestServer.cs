using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh.Tests
{
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

        public async Task<SshClient> CreateClientAsync(Action<SshClientSettings> configure = null)
        {
            var settings = new SshClientSettings();
            IPEndPoint ipEndPoint = _serverSocket.LocalEndPoint as IPEndPoint;
            settings.Host = ipEndPoint.Address.ToString();
            settings.Port = ipEndPoint.Port;
            configure?.Invoke(settings);

            var client = new SshClient(settings);

            await client.ConnectAsync();

            return client;
        }

        private async Task HandleClientAsync()
        {
            Socket clientSocket = await _serverSocket.AcceptAsync();
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
}