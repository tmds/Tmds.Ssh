using System.Text;

using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class SshDataStreamTests
{
    const int SocatStartDelay = 100;

    private readonly SshServer _sshServer;

    public SshDataStreamTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task TcpConnection()
    {
        using var client = await _sshServer.CreateClientAsync();

        // start a an echo server using socat.
        const int socatPort = 1234;
        using var soCatProcess = await client.ExecuteAsync($"socat -v tcp-l:{socatPort},fork exec:'/bin/cat'");
        await Task.Delay(SocatStartDelay); // wait a little for socat to start.

        using var connection = await client.OpenTcpConnectionAsync("localhost", socatPort);

        byte[] helloWorldBytes = Encoding.UTF8.GetBytes("hello world");
        await connection.WriteAsync(helloWorldBytes);

        byte[] receiveBuffer = new byte[128];
        int bytesRead = await connection.ReadAsync(receiveBuffer);

        Assert.Equal(helloWorldBytes.Length, bytesRead);
        Assert.Equal(helloWorldBytes, receiveBuffer.AsSpan(0, bytesRead).ToArray());
    }

    [Fact]
    public async Task TcpConnectionFail()
    {
        using var client = await _sshServer.CreateClientAsync();

        await Assert.ThrowsAsync<SshChannelException>(() => client.OpenTcpConnectionAsync("localhost", 2000));
    }

    [Fact]
    public async Task UnixConnection()
    {
        using var client = await _sshServer.CreateClientAsync();

        // start a an echo server using socat.
        const string socketPath = "/tmp/mysocket";
        using var soCatProcess = await client.ExecuteAsync($"socat -v unix-l:{socketPath},fork exec:'/bin/cat'");
        await Task.Delay(SocatStartDelay); // wait a little for socat to start.

        using var connection = await client.OpenUnixConnectionAsync(socketPath);

        byte[] helloWorldBytes = Encoding.UTF8.GetBytes("hello world");
        await connection.WriteAsync(helloWorldBytes);

        byte[] receiveBuffer = new byte[128];
        int bytesRead = await connection.ReadAsync(receiveBuffer);

        Assert.Equal(helloWorldBytes.Length, bytesRead);
        Assert.Equal(helloWorldBytes, receiveBuffer.AsSpan(0, bytesRead).ToArray());
    }

    [Theory]
    [InlineData("*", 5000, true)]
    [InlineData("127.0.0.1", 6000, false)]
    [InlineData("localhost", 7000, true)]
    [InlineData("localhost", 0, false)]
    public async Task ListenTcp(string address, int port, bool closeConnectionFirst)
    {
        byte[] helloWorldBytes = Encoding.UTF8.GetBytes("hello world");
        byte[] receiveBuffer = new byte[128];
        int bytesRead;

        using var client = await _sshServer.CreateClientAsync();

        // Start listening.
        using var listener = await client.ListenTcpAsync(address, port);
        RemoteIPListenEndPoint? listenEndPoint = listener.ListenEndPoint as RemoteIPListenEndPoint;
        Assert.NotNull(listenEndPoint);
        Assert.Equal(address, listenEndPoint.Address);
        if (port == 0)
        {
            port = listenEndPoint.Port;
            Assert.NotEqual(0, port);
        }
        else
        {
            Assert.Equal(port, listenEndPoint.Port);
        }

        // Open a connection.
        using var connection = await client.OpenTcpConnectionAsync("localhost", port);

        // Accept the connection on the listener as 'stream'.
        using var remoteConnection = await listener.AcceptAsync();
        Assert.True(remoteConnection.HasStream);
        using var stream = remoteConnection.MoveStream();
        Assert.False(remoteConnection.HasStream);

        // Write connection -> stream
        await connection.WriteAsync(helloWorldBytes);
        bytesRead = await stream.ReadAsync(receiveBuffer);
        Assert.Equal(helloWorldBytes.Length, bytesRead);
        Assert.Equal(helloWorldBytes, receiveBuffer.AsSpan(0, bytesRead).ToArray());

        // Write stream -> connection
        await stream.WriteAsync(helloWorldBytes);
        receiveBuffer.AsSpan().Clear();
        bytesRead = await connection.ReadAsync(receiveBuffer);
        Assert.Equal(helloWorldBytes.Length, bytesRead);
        Assert.Equal(helloWorldBytes, receiveBuffer.AsSpan(0, bytesRead).ToArray());

        if (closeConnectionFirst)
        {
            // Close connection -> stream
            connection.Dispose();
            bytesRead = await stream.ReadAsync(receiveBuffer);
            Assert.Equal(0, bytesRead);
            stream.Dispose();
        }
        else
        {
            // Close stream -> connection
            stream.Dispose();
            bytesRead = await connection.ReadAsync(receiveBuffer);
            Assert.Equal(0, bytesRead);
            connection.Dispose();
        }

        // Stop the listener.
        listener.Dispose();
        await Assert.ThrowsAsync<SshChannelException>(async () =>
        {
            using var connection = await client.OpenTcpConnectionAsync("localhost", port);
        });
    }

    [Fact]
    public async Task RemoteListener_AcceptOnDispose()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var listener = await client.ListenTcpAsync("localhost", 0);

        var pendingAccept = listener.AcceptAsync();

        listener.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () => { using var _ = await pendingAccept; });
    }

    [Fact]
    public async Task RemoteListener_AcceptOnClientClose()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var listener = await client.ListenTcpAsync("localhost", 0);

        var pendingAccept = listener.AcceptAsync();

        client.Dispose();

        await Assert.ThrowsAsync<SshConnectionClosedException>(async () => { using var _ = await pendingAccept; });
    }

    [Fact]
    public async Task RemoteListener_AcceptOnStop()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var listener = await client.ListenTcpAsync("localhost", 0);

        var pendingAccept = listener.AcceptAsync();

        listener.Stop();

        using RemoteConnection conn1 = await pendingAccept;
        Assert.False(conn1.HasStream);

        listener.Dispose();

        using RemoteConnection conn2 = await pendingAccept;
        Assert.False(conn2.HasStream);
    }
}
