using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit;

namespace Tmds.Ssh.Tests
{
    public class ConnectTests
    {
        [Fact]
        public async Task ClientCanConnectToServerSocket()
        {
            using (Socket listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                listenSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                listenSocket.Listen(1);

                IPEndPoint localEndPoint = listenSocket.LocalEndPoint as IPEndPoint;

                var clientSettings = new SshClientSettings
                {
                    Host = localEndPoint.Address.ToString(),
                    Port = localEndPoint.Port,
                    SetupConnectionAsync = SshClientSettings.NoSetup
                };

                await using var sshClient = new SshClient(clientSettings);
                await sshClient.ConnectAsync();

                listenSocket.Blocking = false;
                Socket acceptedSocket = listenSocket.Accept();

                await sshClient.DisposeAsync();

                int bytesReceived = acceptedSocket.Receive(new byte[1]);
                Assert.Equal(0, bytesReceived);
            }
        }
    }
}
