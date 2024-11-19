using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class KeepAliveTests
{
    private readonly SshServer _sshServer;

    public KeepAliveTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task KeepAliveTimeOutClosesConnection(bool enableKeepAlive)
    {
        TimeSpan keepAliveInterval = TimeSpan.FromMilliseconds(500);
        int keepAliveCountMax = 3;

        // Establish a proxied connection.
        using TcpListener proxyServer = new TcpListener(IPAddress.Loopback, 0);
        proxyServer.Start();
        IPEndPoint localEndPoint = (IPEndPoint)proxyServer.LocalEndpoint;
        string destination = $"{_sshServer.TestUser}@{localEndPoint.Address}:{localEndPoint.Port}";
        var settings = new SshClientSettings(destination)
        {
            HostAuthentication = delegate { return ValueTask.FromResult(true); },
            Credentials = [ new PasswordCredential(_sshServer.TestUserPassword) ],
            KeepAliveCountMax = keepAliveCountMax,
            KeepAliveInterval = enableKeepAlive ? keepAliveInterval : TimeSpan.Zero
        };
        using var client = new SshClient(settings);
        Task connectTask = client.ConnectAsync();
        using ProxyConnection proxyConnection = new ProxyConnection(await proxyServer.AcceptSocketAsync());
        proxyConnection.ProxyTo(_sshServer.ServerHost, _sshServer.ServerPort);
        await connectTask;

        // Keep the TCP connection but stop relaying data.
        proxyConnection.StopProxying();

        // Start a command.
        long startTime = Stopwatch.GetTimestamp();
        Task executeHello = client.ExecuteAsync("echo 'hello world'");

        // Task that times out after the keep alive.
        Task timeoutTask = Task.Delay(keepAliveInterval * (keepAliveCountMax + 1) + TimeSpan.FromSeconds(1));

        Task completedTask = await Task.WhenAny(executeHello, timeoutTask);
        if (enableKeepAlive)
        {
            TimeSpan elapsedTime = Stopwatch.GetElapsedTime(startTime);
            Assert.Equal(executeHello, completedTask);
            Assert.True(elapsedTime > keepAliveInterval * keepAliveCountMax);
            await Assert.ThrowsAsync<SshConnectionClosedException>(() => completedTask);
        }
        else
        {
            Assert.Equal(timeoutTask, timeoutTask);

            Assert.False(executeHello.IsCompleted);
            client.Dispose();
            await Assert.ThrowsAsync<SshConnectionClosedException>(() => executeHello);
        }
    }

    private class ProxyConnection : IDisposable
    {
        private readonly Socket _socket;
        private readonly CancellationTokenSource _cts = new();
        private Socket? _proxySocket;

        public ProxyConnection(Socket socket)
            => _socket = socket;

        public void StopProxying()
        {
            _cts.Cancel();
        }

        public void ProxyTo(string host, int port)
        {
            _proxySocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _proxySocket.Connect(host, port);
            _ = RelayDataAsync(_socket, _proxySocket, _cts.Token);
            _ = RelayDataAsync(_proxySocket, _socket, _cts.Token);
        }

        private static async Task RelayDataAsync(Socket source, Socket destination, CancellationToken cancellationToken)
        {
            try
            {
                var buffer = new byte[4096];
                while (!cancellationToken.IsCancellationRequested)
                {
                    int bytesRead = await source.ReceiveAsync(buffer, SocketFlags.None, cancellationToken);
                    if (bytesRead == 0)
                    {
                        break;
                    }

                    await destination.SendAsync(new ArraySegment<byte>(buffer, 0, bytesRead), SocketFlags.None, cancellationToken);
                }
            }
            catch (OperationCanceledException)
            { }
        }

        public void Dispose()
        {
            _socket.Dispose();
            _proxySocket?.Dispose();
        }
    }
}
