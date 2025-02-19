using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class RemoteForwardTests
{
    private readonly SshServer _sshServer;

    public RemoteForwardTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ForwardsTcp(bool useLocalDnsEndpoint)
    {
        using var client = await _sshServer.CreateClientAsync();

        using var echoServer = new EchoServer();

        EndPoint localEndPoint = echoServer.EndPoint;
        if (useLocalDnsEndpoint)
        {
            localEndPoint = new DnsEndPoint("localhost", (localEndPoint as IPEndPoint)!.Port);
        }

        using var remoteForward = await client.StartRemoteForwardAsync(new RemoteIPListenEndPoint("localhost", 0), localEndPoint);
        await AssertForwards(client, remoteForward);
    }

    [Fact]
    public async Task ForwardsUnix()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var echoServer = new EchoServer(AddressFamily.Unix);

        EndPoint localEndPoint = echoServer.EndPoint;

        using var remoteForward = await client.StartRemoteForwardAsync(new RemoteUnixEndPoint($"/tmp/{Path.GetRandomFileName()}"), localEndPoint);
        await AssertForwards(client, remoteForward);
    }

    private async Task AssertForwards(SshClient client, RemoteForward remoteForward)
    {
        byte[] helloWorldBytes = Encoding.UTF8.GetBytes("hello world");
        byte[] receiveBuffer = new byte[128];
        for (int i = 0; i < 2; i++)
        {
            RemoteEndPoint endPoint = remoteForward.RemoteEndPoint;
            SshDataStream? clientStream = null;
            if (endPoint is RemoteIPListenEndPoint ipEndPoint)
            {
                string host = ipEndPoint.Address;
                if (host == "*")
                {
                    host = "localhost";
                }
                clientStream = await client.OpenTcpConnectionAsync(host, ipEndPoint.Port);
            }
            else if (endPoint is RemoteUnixEndPoint unixEndPoint)
            {
                clientStream = await client.OpenUnixConnectionAsync(unixEndPoint.Path);
            }
            Assert.NotNull(clientStream);
            using var _ = clientStream;

            for (int j = 0; j < 2; j++)
            {
                await clientStream.WriteAsync(helloWorldBytes);

                int bytesRead = await clientStream.ReadAsync(receiveBuffer);
                Assert.Equal(helloWorldBytes.Length, bytesRead);
                Assert.Equal(helloWorldBytes, receiveBuffer.AsSpan(0, bytesRead).ToArray());
            }

            clientStream.WriteEof();
            int received =  await clientStream.ReadAsync(receiveBuffer);
            Assert.Equal(0, received);
        }
    }

    [Fact]
    public async Task StopsWhenDisposed()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var remoteForward = await client.StartRemoteForwardAsync(new RemoteIPListenEndPoint("localhost", 0), new IPEndPoint(IPAddress.Loopback, 5000));
        CancellationToken ct = remoteForward.Stopped;
        RemoteIPListenEndPoint? endPoint = remoteForward.RemoteEndPoint as RemoteIPListenEndPoint;

        Assert.False(ct.IsCancellationRequested);
        Assert.NotNull(endPoint);

        remoteForward.Dispose();

        Assert.True(ct.IsCancellationRequested);
        Assert.Throws<ObjectDisposedException>(() => remoteForward.RemoteEndPoint);
        Assert.Throws<ObjectDisposedException>(() => remoteForward.Stopped);
        Assert.Throws<ObjectDisposedException>(() => remoteForward.ThrowIfStopped());

        await Assert.ThrowsAnyAsync<SshChannelException>(async () => await client.OpenTcpConnectionAsync(endPoint.Address, endPoint.Port));
    }

    [Fact]
    public async Task StopsWhenClientDisconnects()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var remoteForward = await client.StartRemoteForwardAsync(new RemoteIPListenEndPoint("localhost", 0), new IPEndPoint(IPAddress.Loopback, 5000));
        CancellationToken ct = remoteForward.Stopped;
        RemoteIPListenEndPoint? endPoint = remoteForward.RemoteEndPoint as RemoteIPListenEndPoint;

        Assert.False(ct.IsCancellationRequested);
        Assert.NotNull(endPoint);

        client.Dispose();

        Assert.True(ct.IsCancellationRequested);
        Assert.NotNull(remoteForward.RemoteEndPoint);
        Assert.True(remoteForward.Stopped.IsCancellationRequested);
        Assert.Throws<SshConnectionClosedException>(() => remoteForward.ThrowIfStopped());
    }
}
