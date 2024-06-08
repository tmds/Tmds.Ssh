using System;
using System.Threading.Tasks;
using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class SshClientTests
{
    private readonly SshServer _sshServer;

    public SshClientTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task AutoConnect(bool autoConnect)
    {
        using var client = await _sshServer.CreateClientAsync(
            configure: settings => settings.AutoConnect = autoConnect,
            connect: false
        );

        if (autoConnect)
        {
            using var sftpClient = await client.OpenSftpClientAsync();
        }
        else
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => client.OpenSftpClientAsync());
        }
    }

    [Fact]
    public async Task AutoConnectAllowsExplicitConnectBeforeImplicitConnect()
    {
        using var client = await _sshServer.CreateClientAsync(
            configure: settings => settings.AutoConnect = true,
            connect: false
        );

        await client.ConnectAsync();

        using var sftpClient = await client.OpenSftpClientAsync();
    }

    [Fact]
    public async Task AutoConnectDisallowsExplicitConnectAfterImplicitConnect()
    {
        // If a user calls ConnectAsync, we require it to happen before performing operations.
        // If there is an issue connecting, this ConnectAsync will throw the connect exception.
        // And, its cancellation token enables cancelling the connect.
        using var client = await _sshServer.CreateClientAsync(
            configure: settings => settings.AutoConnect = true,
            connect: false
        );

        var pending = client.OpenSftpClientAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ConnectAsync());
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task AutoReconnect(bool autoReconnect)
    {
        using var client = await _sshServer.CreateClientAsync(
            configure: settings => settings.AutoReconnect = autoReconnect
        );

        using var sftpClient = await client.OpenSftpClientAsync();

        client.ForceConnectionClose();

        if (autoReconnect)
        {
            using var sftpClient2 = await client.OpenSftpClientAsync();
        }
        else
        {
            await Assert.ThrowsAsync<SshConnectionClosedException>(() => client.OpenSftpClientAsync());
        }
    }
}
