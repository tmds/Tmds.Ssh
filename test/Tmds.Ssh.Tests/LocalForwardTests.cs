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

        using var directForward = await client.StartForwardAsync(new IPEndPoint(IPAddress.Loopback, 0), new RemoteDnsEndPoint("localhost", socatPort));
        await AssertForwards(directForward);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ForwardsSocks(bool useIP)
    {
        using var client = await _sshServer.CreateClientAsync();

        // start a an echo server using socat.
        const int socatPort = 1234;
        using var soCatProcess = await client.ExecuteAsync($"socat -v tcp-l:{socatPort},fork exec:'/bin/cat'");
        await Task.Delay(SocatStartDelay); // wait a little for socat to start.

        using var socksForward = await client.StartSocksForward(new IPEndPoint(IPAddress.Loopback, 0));
        await AssertForwards(socksForward, useIP ? IPAddress.Loopback : null, useIP ? null : "localhost", socatPort);
    }

    [Fact]
    public async Task ForwardsUnix()
    {
        using var client = await _sshServer.CreateClientAsync();

        // start a an echo server using socat.
        const string socketPath = "/tmp/mysocket";
        using var soCatProcess = await client.ExecuteAsync($"socat -v unix-l:{socketPath},fork exec:'/bin/cat'");
        await Task.Delay(SocatStartDelay); // wait a little for socat to start.

        using var directForward = await client.StartForwardAsync(new IPEndPoint(IPAddress.Loopback, 0), new RemoteUnixEndPoint(socketPath));
        await AssertForwards(directForward);
    }

    [Fact]
    public async Task BindUnixSocket()
    {
        using var client = await _sshServer.CreateClientAsync();

        // start a an echo server using socat.
        const int socatPort = 1234;
        using var soCatProcess = await client.ExecuteAsync($"socat -v tcp-l:{socatPort},fork exec:'/bin/cat'");
        await Task.Delay(SocatStartDelay); // wait a little for socat to start.

        var ep = new UnixDomainSocketEndPoint(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()));
        using var directForward = await client.StartForwardAsync(ep, new RemoteDnsEndPoint("localhost", socatPort));
        await AssertForwards(directForward);
    }

    private async Task AssertForwards(DirectForward directForward)
    {
        byte[] helloWorldBytes = Encoding.UTF8.GetBytes("hello world");
        byte[] receiveBuffer = new byte[128];
        for (int i = 0; i < 2; i++)
        {
            EndPoint endPoint = directForward.LocalEndPoint!;
            using var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, endPoint.AddressFamily == AddressFamily.InterNetwork ? ProtocolType.Tcp : ProtocolType.Unspecified);
            if (socket.ProtocolType == ProtocolType.Tcp)
            {
                socket.NoDelay = true;
            }
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

    private async Task AssertForwards(SocksForward socksForward, IPAddress? remoteIP, string? remoteHost, int remotePort)
    {
        byte[] helloWorldBytes = Encoding.UTF8.GetBytes("hello world");
        byte[] receiveBuffer = new byte[128];

        EndPoint endPoint = socksForward.LocalEndPoint!;
        using var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, endPoint.AddressFamily == AddressFamily.InterNetwork ? ProtocolType.Tcp : ProtocolType.Unspecified);
        if (socket.ProtocolType == ProtocolType.Tcp)
        {
            socket.NoDelay = true;
        }
        await socket.ConnectAsync(endPoint);

        await DoSocksConnectAsync(socket, remoteIP, remoteHost, remotePort);

        await socket.SendAsync(helloWorldBytes);

        int bytesRead = await socket.ReceiveAsync(receiveBuffer);
        Assert.Equal(helloWorldBytes.Length, bytesRead);
        Assert.Equal(helloWorldBytes, receiveBuffer.AsSpan(0, bytesRead).ToArray());

        socket.Shutdown(SocketShutdown.Send);
        int received =  await socket.ReceiveAsync(receiveBuffer);
        Assert.Equal(0, received);
    }

    private async Task DoSocksConnectAsync(Socket socket, IPAddress? remoteIP, string? remoteHost, int remotePort)
    {
            byte[] buffer = new byte[512];

            //  +----+----------+----------+
            //  |VER | NMETHODS | METHODS  |
            //  +----+----------+----------+
            //  | 1  |    1     | 1 to 255 |
            //  +----+----------+----------+
            await socket.SendAsync(new byte[] { 5, 2, 0, 1 }); // V5 No Auth or GSSAPI auth.

            //  +----+--------+
            //  |VER | METHOD |
            //  +----+--------+
            //  | 1  |   1    |
            //  +----+--------+
            int bytesRead = await socket.ReceiveAsync(buffer.AsMemory(0, 2));
            Assert.Equal(2, bytesRead);
            Assert.Equal(5, buffer[0]); // v5
            Assert.Equal(0, buffer[1]); // no auth

            // +----+-----+-------+------+----------+----------+
            // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            buffer[0] = 5;
            buffer[1] = 1;
            buffer[2] = 0;
            int portOffset = 0;
            if (remoteIP is not null && remoteIP.AddressFamily == AddressFamily.InterNetwork)
            {
                buffer[3] = 1; // IPv4
                remoteIP.TryWriteBytes(buffer.AsSpan(4), out _);
                portOffset = 8;
            }
            else if (remoteIP is not null && remoteIP.AddressFamily == AddressFamily.InterNetwork)
            {
                buffer[3] = 4; // IPv6
                remoteIP.TryWriteBytes(buffer.AsSpan(4), out _);
                portOffset = 20;
            }
            else
            {
                Assert.NotNull(remoteHost);
                buffer[3] = 3; // Domain name
                int bytesWritten = Encoding.UTF8.GetBytes(remoteHost, buffer.AsSpan(5));
                buffer[4] = (byte)bytesWritten;
                portOffset = 5 + bytesWritten;
            }
            buffer[portOffset++] = (byte)(remotePort >> 8);
            buffer[portOffset++] = (byte)remotePort;
            await socket.SendAsync(buffer.AsMemory(0, portOffset));

            // +----+-----+-------+------+----------+----------+
            // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            bytesRead = await socket.ReceiveAsync(buffer.AsMemory(0, 10));
            // note: the implementation is always replying with 0.0.0.0:0.
            Assert.Equal(10, bytesRead);
            Assert.Equal(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, buffer.AsMemory(0, 10).ToArray());
    }

    [Fact]
    public async Task StopsWhenDisposed()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var directForward = await client.StartForwardAsync(new IPEndPoint(IPAddress.Loopback, 0), new RemoteDnsEndPoint("localhost", 5000));
        CancellationToken ct = directForward.ForwardStopped;
        EndPoint? endPoint = directForward.LocalEndPoint;

        Assert.False(ct.IsCancellationRequested);    
        Assert.NotNull(endPoint);

        directForward.Dispose();

        Assert.True(ct.IsCancellationRequested);
        Assert.Throws<ObjectDisposedException>(() => directForward.LocalEndPoint);
        Assert.Throws<ObjectDisposedException>(() => directForward.ForwardStopped);
        Assert.Throws<ObjectDisposedException>(() => directForward.ThrowIfStopped());

        using var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await Assert.ThrowsAnyAsync<SocketException>(async () => await socket.ConnectAsync(endPoint));
    }

    [Fact]
    public async Task StopsWhenClientDisconnects()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var directForward = await client.StartForwardAsync(new IPEndPoint(IPAddress.Loopback, 0), new RemoteDnsEndPoint("localhost", 5000));
        CancellationToken ct = directForward.ForwardStopped;
        EndPoint? endPoint = directForward.LocalEndPoint;

        Assert.False(ct.IsCancellationRequested);    
        Assert.NotNull(endPoint);

        client.Dispose();

        Assert.True(ct.IsCancellationRequested);
        Assert.Throws<SshConnectionClosedException>(() => directForward.LocalEndPoint);
        Assert.True(directForward.ForwardStopped.IsCancellationRequested);
        Assert.Throws<SshConnectionClosedException>(() => directForward.ThrowIfStopped());

        using var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await Assert.ThrowsAnyAsync<SocketException>(async () => await socket.ConnectAsync(endPoint));
    }

    [Fact]
    public async Task IPv6IsDualMode()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var directForward = await client.StartForwardAsync(new IPEndPoint(IPAddress.IPv6Any, 0), new RemoteDnsEndPoint("nowhere", 10));
        
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, (directForward.LocalEndPoint as IPEndPoint)!.Port));
    }
}
