using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class LocalForwardTests
{
    const int SocatStartDelay = 100;
    private readonly SshServer _sshServer;

    public LocalForwardTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task Forwards()
    {
        using var client = await _sshServer.CreateClientAsync();

        // start a an echo server using socat.
        const int socatPort = 1234;
        using var soCatProcess = await client.ExecuteAsync($"socat -v tcp-l:{socatPort},fork exec:'/bin/cat'");
        await Task.Delay(SocatStartDelay); // wait a little for socat to start.

        using var localForward = await client.StartForwardTcpAsync(new IPEndPoint(IPAddress.Loopback, 0), "localhost", socatPort);

        byte[] helloWorldBytes = Encoding.UTF8.GetBytes("hello world");
        byte[] receiveBuffer = new byte[128];
        for (int i = 0; i < 2; i++)
        {
            EndPoint endPoint = localForward.EndPoint!;
            using var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(endPoint);

            for (int j = 0; j < 2; j++)
            {
                await socket.SendAsync(helloWorldBytes);

                int bytesRead = await socket.ReceiveAsync(receiveBuffer);
                Assert.Equal(helloWorldBytes.Length, bytesRead);
                Assert.Equal(helloWorldBytes, receiveBuffer.AsSpan(0, bytesRead).ToArray());
            }

            socket.Shutdown(SocketShutdown.Send);
            int received =  await socket.ReceiveAsync(receiveBuffer);
            Assert.Equal(0, received);
        }
    }
}
