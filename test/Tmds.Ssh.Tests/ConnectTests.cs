using System;
using Xunit;

using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class ConnectTests
{
    private readonly SshServer _sshServer;

    [Fact]
    public async Task ClientCanConnectToServerSocket()
    {
        TaskCompletionSource<Packet> serverReceivedTcs = new TaskCompletionSource<Packet>();

        await using var server = new TestServer(
            async conn =>
            {
                var packet = await conn.ReceivePacketAsync(default).ConfigureAwait(false);
                serverReceivedTcs.SetResult(packet);
            }
        );
        using var client = await server.CreateClientAsync(
            s =>
            {
                s.NoKeyExchange = true;
                s.NoProtocolVersionExchange = true;
                s.NoUserAuthentication = true;
            }
        );
        client.Dispose();

        // Check the server received an EOF.
        var serverReceivedPacket = await serverReceivedTcs.Task;
        Assert.True(serverReceivedPacket.IsEmpty);
    }

    public ConnectTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task ConnectSuccess()
    {
        using var _ = await _sshServer.CreateClientAsync();
    }

    [Fact]
    public async Task UnknownHostConnectThrows()
    {
        await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(settings =>
                settings.UserKnownHostsFilePaths = [ "/" ]
            ));
    }

    [Fact]
    public async Task KeyVerificationHasConnectionInfo()
    {
        using var _ = await _sshServer.CreateClientAsync(settings =>
            {
                settings.UserKnownHostsFilePaths = [ "/" ];
                settings.HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    Assert.Equal(KnownHostResult.Unknown, knownHostResult);
                    Assert.Equal(_sshServer.ServerHost, connectionInfo.HostName);
                    Assert.Equal(_sshServer.ServerPort, connectionInfo.Port);
                    string[] serverKeyFingerPrints =
                    [
                        _sshServer.RsaKeySHA256FingerPrint,
                            _sshServer.Ed25519KeySHA256FingerPrint,
                            _sshServer.EcdsaKeySHA256FingerPrint
                    ];
                    Assert.Contains(serverKeyFingerPrints, key => key == connectionInfo.ServerKey.SHA256FingerPrint);
                    return ValueTask.FromResult(true);
                };
            }
        );
    }

    [Fact]
    public async Task NoKnownHosts()
    {
        using var _ = await _sshServer.CreateClientAsync(settings =>
            {
                settings.UserKnownHostsFilePaths = [];
                settings.GlobalKnownHostsFilePaths = [];
                settings.HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    return ValueTask.FromResult(true);
                };
            }
        );
    }

    [Fact]
    public async Task UntrustedKeyVerificationThrows()
    {
        await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(settings =>
            {
                settings.UserKnownHostsFilePaths = [ "/" ];
                settings.HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    return ValueTask.FromResult(false);
                };
            }
        ));
    }

    [Fact]
    public async Task AddKnownHost()
    {
        string knownHostsFileName = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            Assert.False(File.Exists(knownHostsFileName));

            bool keyVerified = false;
            SshClient client = await _sshServer.CreateClientAsync(settings =>
                {
                    settings.UserKnownHostsFilePaths = [ knownHostsFileName ];
                    settings.HostAuthentication =
                    (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                    {
                        keyVerified = true;
                        Assert.Equal(KnownHostResult.Unknown, knownHostResult);
                        return ValueTask.FromResult(true);
                    };
                    settings.UpdateKnownHostsFileAfterAuthentication = true;
                });
            client.Dispose();
            Assert.True(keyVerified);
            Assert.True(File.Exists(knownHostsFileName));

            client = await _sshServer.CreateClientAsync(settings =>
            {
                settings.UserKnownHostsFilePaths = [ knownHostsFileName ];
                settings.HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    Assert.True(false);
                    return ValueTask.FromResult(knownHostResult == KnownHostResult.Trusted);
                };
            });
            client.Dispose();
        }
        finally
        {
            try
            {
                File.Delete(knownHostsFileName);
            }
            catch
            { }
        }
    }

    [Fact]
    public async Task NoCredentialsConnectThrows()
    {
        await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(settings =>
                settings.Credentials = []
            ));
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task PasswordCredential(bool correctPassword)
    {
        var settings = new SshClientSettings(_sshServer.Destination)
        {
            UserKnownHostsFilePaths = [ _sshServer.KnownHostsFilePath ],
            Credentials = [ new PasswordCredential(correctPassword ? _sshServer.TestUserPassword : "invalid") ],
        };
        using var client = new SshClient(settings);

        if (correctPassword)
        {
            await client.ConnectAsync();
        }
        else
        {
            await Assert.ThrowsAnyAsync<SshConnectionException>(() => client.ConnectAsync());
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(1000)]
    public async Task Timeout(int msTimeout)
    {
        IPAddress address = IPAddress.Loopback;
        using var s = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        s.Bind(new IPEndPoint(address, 0));
        s.Listen();
        int port = (s.LocalEndPoint as IPEndPoint)!.Port;

        using var client = new SshClient(
            new SshClientSettings($"user@{address}:{port}")
            {
                ConnectTimeout = TimeSpan.FromMilliseconds(msTimeout)
            });
        SshConnectionException exception = await Assert.ThrowsAnyAsync<SshConnectionException>(() => client.ConnectAsync());
        Assert.IsType<TimeoutException>(exception.InnerException);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1000)]
    public async Task CancelConnect(int msTimeout)
    {
        IPAddress address = IPAddress.Loopback;
        using var s = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        s.Bind(new IPEndPoint(address, 0));
        s.Listen();
        int port = (s.LocalEndPoint as IPEndPoint)!.Port;

        using var client = new SshClient($"user@{address}:{port}", SshConfigOptions.NoConfig);

        CancellationTokenSource cts = new();
        cts.CancelAfter(msTimeout);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ConnectAsync(cts.Token));
    }

    [Fact]
    public async Task CancelVerification()
    {
        CancellationTokenSource cts = new();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _sshServer.CreateClientAsync(settings =>
            {
                settings.UserKnownHostsFilePaths = [ "/" ];
                settings.HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    cts.Cancel();
                    Assert.True(cancellationToken.IsCancellationRequested);
                    cancellationToken.ThrowIfCancellationRequested();
                    return ValueTask.FromResult(true);
                };
            }, cts.Token
        ));
    }

    [Fact]
    public async Task CancelAuthentication()
    {
        CancellationTokenSource cts = new();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _sshServer.CreateClientAsync(settings =>
            {
                settings.UserKnownHostsFilePaths = [ "/" ];
                settings.HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    cts.Cancel();
                    return ValueTask.FromResult(true);
                };
            }, cts.Token
        ));
    }

    [Fact]
    public async Task VerificationExceptionWrapped()
    {
        var exceptionThrown = new Exception("Any exception");

        CancellationTokenSource cts = new();
        var ex = await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(settings =>
            {
                settings.UserKnownHostsFilePaths = [ "/" ];
                settings.HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    throw exceptionThrown;
                };
            }, cts.Token
        ));
        Assert.IsNotType<SshConnectionClosedException>(ex);

        Assert.Equal(exceptionThrown, ex.InnerException);
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

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task SshConfig_AutoConnect(bool autoConnect)
    {
        using var client = await _sshServer.CreateClientAsync(
            new SshConfigOptions([_sshServer.SshConfigFilePath])
            {
                AutoConnect = autoConnect
            },
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

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task SshConfig_AutoReconnect(bool autoReconnect)
    {
        using var client = await _sshServer.CreateClientAsync(
            new SshConfigOptions([_sshServer.SshConfigFilePath])
            {
                AutoReconnect = autoReconnect
            }
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

    [Theory]
    [InlineData(1)]
    [InlineData(1000)]
    public async Task SshConfig_Timeout(int msTimeout)
    {
        IPAddress address = IPAddress.Loopback;
        using var s = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        s.Bind(new IPEndPoint(address, 0));
        s.Listen();
        int port = (s.LocalEndPoint as IPEndPoint)!.Port;

        using var client = new SshClient($"user@{address}:{port}",
            new SshConfigOptions([_sshServer.SshConfigFilePath])
            {
                ConnectTimeout = TimeSpan.FromMilliseconds(msTimeout)
            });

        SshConnectionException exception = await Assert.ThrowsAnyAsync<SshConnectionException>(() => client.ConnectAsync());
        Assert.IsType<TimeoutException>(exception.InnerException);
    }

    [Fact]
    public async Task SshConfig_ConnectFailure()
    {
        await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(SshConfigOptions.NoConfig));
    }

    [Fact]
    public async Task SshConfig_HostAuthentication()
    {
        using TempFile tempFile = new TempFile(Path.GetTempFileName());
        File.WriteAllText(tempFile.Path,
            $"""
            IdentityFile "{_sshServer.TestUserIdentityFile}"
            """);
        using var _ = await _sshServer.CreateClientAsync(
            new SshConfigOptions([tempFile.Path])
            {
                HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    Assert.Equal(KnownHostResult.Unknown, knownHostResult);
                    Assert.Equal(_sshServer.ServerHost, connectionInfo.HostName);
                    Assert.Equal(_sshServer.ServerPort, connectionInfo.Port);
                    string[] serverKeyFingerPrints =
                    [
                        _sshServer.RsaKeySHA256FingerPrint,
                            _sshServer.Ed25519KeySHA256FingerPrint,
                            _sshServer.EcdsaKeySHA256FingerPrint
                    ];
                    Assert.Contains(serverKeyFingerPrints, key => key == connectionInfo.ServerKey.SHA256FingerPrint);
                    return ValueTask.FromResult(true);
                }
            }
        );
    }
}
