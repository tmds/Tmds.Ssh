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
    public async Task ForwardsTcp()
    {
        using var client = await _sshServer.CreateClientAsync();

        // start a an echo server using socat.
        const int socatPort = 1234;
        using var soCatProcess = await client.ExecuteAsync($"socat -v tcp-l:{socatPort},fork exec:'/bin/cat'");
        await Task.Delay(SocatStartDelay); // wait a little for socat to start.

        using var localForward = await client.StartForwardTcpAsync(new IPEndPoint(IPAddress.Loopback, 0), "localhost", socatPort);
        await AssertForwards(localForward);
    }

    [Fact]
    public async Task ForwardsUnix()
    {
        using var client = await _sshServer.CreateClientAsync();

        // start a an echo server using socat.
        const string socketPath = "/tmp/mysocket";
        using var soCatProcess = await client.ExecuteAsync($"socat -v unix-l:{socketPath},fork exec:'/bin/cat'");
        await Task.Delay(SocatStartDelay); // wait a little for socat to start.

        using var localForward = await client.StartForwardUnixAsync(new IPEndPoint(IPAddress.Loopback, 0), socketPath);
        await AssertForwards(localForward);
    }

    private async Task AssertForwards(LocalForward localForward)
    {
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

    [Fact]
    public async Task StopsWhenDisposed()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var localForward = await client.StartForwardTcpAsync(new IPEndPoint(IPAddress.Loopback, 0), "localhost", 5000);
        CancellationToken ct = localForward.ForwardStopped;
        EndPoint? endPoint = localForward.EndPoint;

        Assert.False(ct.IsCancellationRequested);    
        Assert.NotNull(endPoint);

        localForward.Dispose();

        Assert.True(ct.IsCancellationRequested);
        Assert.Throws<ObjectDisposedException>(() => localForward.EndPoint);
        Assert.Throws<ObjectDisposedException>(() => localForward.ForwardStopped);
        Assert.Throws<ObjectDisposedException>(() => localForward.ThrowIfStopped());

        using var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await Assert.ThrowsAnyAsync<SocketException>(async () => await socket.ConnectAsync(endPoint));
    }

    [Fact]
    public async Task StopsWhenClientDisconnects()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var localForward = await client.StartForwardTcpAsync(new IPEndPoint(IPAddress.Loopback, 0), "localhost", 5000);
        CancellationToken ct = localForward.ForwardStopped;
        EndPoint? endPoint = localForward.EndPoint;

        Assert.False(ct.IsCancellationRequested);    
        Assert.NotNull(endPoint);

        client.Dispose();

        Assert.True(ct.IsCancellationRequested);
        Assert.Null(localForward.EndPoint);
        Assert.True(localForward.ForwardStopped.IsCancellationRequested);
        Assert.Throws<SshConnectionClosedException>(() => localForward.ThrowIfStopped());

        using var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await Assert.ThrowsAnyAsync<SocketException>(async () => await socket.ConnectAsync(endPoint));
    } 
}
