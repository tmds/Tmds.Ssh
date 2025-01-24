using Xunit;
using System.Net;
using System.Net.Sockets;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class ConnectTests
{
    private readonly SshServer _sshServer;

    public ConnectTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task ConnectSuccess()
    {
        using var client = await _sshServer.CreateClientAsync();

        Assert.True(client.ConnectionInfo.UseStrictKex);
    }

    [Fact]
    public async Task UnknownHostConnectThrows()
    {
        await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(settings =>
                settings.UserKnownHostsFilePaths = [ "/no_such_file" ]
            ));
    }

    [Fact]
    public async Task KeyVerificationHasConnectionInfo()
    {
        using var _ = await _sshServer.CreateClientAsync(settings =>
            {
                settings.UserKnownHostsFilePaths = [ "/no_such_file" ];
                settings.HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    Assert.Equal(KnownHostResult.Unknown, knownHostResult);
                    Assert.Equal(_sshServer.ServerHost, connectionInfo.HostName);
                    Assert.Equal(_sshServer.ServerPort, connectionInfo.Port);
                    Assert.Contains(_sshServer.ServerKeySHA256FingerPrints, key => key == connectionInfo.ServerKey.SHA256FingerPrint);
                    bool isCertificate = _sshServer.ServerKeyCertSHA256FingerPrints.Contains(connectionInfo.ServerKey.CertInfo?.CertificateKey?.SHA256FingerPrint ?? "");
                    Assert.Equal(isCertificate ? _sshServer.CaSHA256FingerPrint : null, connectionInfo.ServerKey.IssuerSHA256FingerPrint);
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
                settings.UserKnownHostsFilePaths = [ "/no_such_file" ];
                settings.HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    return ValueTask.FromResult(false);
                };
            }
        ));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AddKnownHost(bool hashKnownHosts)
    {
        string knownHostsFileName = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            Assert.False(File.Exists(knownHostsFileName));

            bool keyVerified = false;
            SshClient client = await _sshServer.CreateClientAsync(settings =>
                {
                    settings.UserKnownHostsFilePaths = [ knownHostsFileName ];
                    settings.HashKnownHosts = hashKnownHosts;
                    settings.HostAuthentication =
                    (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                    {
                        keyVerified = true;
                        Assert.Equal(KnownHostResult.Unknown, knownHostResult);
                        return ValueTask.FromResult(true);
                    };
                    settings.ServerHostKeyAlgorithms = [ AlgorithmNames.RsaSshSha2_256 ];
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

        using var client = new SshClient($"user@{address}:{port}", SshConfigSettings.NoConfig);

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
                settings.UserKnownHostsFilePaths = [ "/no_such_file" ];
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
                settings.UserKnownHostsFilePaths = [ "/no_such_file" ];
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
                settings.UserKnownHostsFilePaths = [ "/no_such_file" ];
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
            new SshConfigSettings()
            {
                AutoConnect = autoConnect,
                ConfigFilePaths = [ _sshServer.SshConfigFilePath ]
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
            new SshConfigSettings()
            {
                AutoReconnect = autoReconnect,
                ConfigFilePaths = [ _sshServer.SshConfigFilePath ]
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
            new SshConfigSettings()
            {
                ConnectTimeout = TimeSpan.FromMilliseconds(msTimeout),
                ConfigFilePaths = [ _sshServer.SshConfigFilePath ]
            });

        SshConnectionException exception = await Assert.ThrowsAnyAsync<SshConnectionException>(() => client.ConnectAsync());
        Assert.IsType<TimeoutException>(exception.InnerException);
    }

    [Fact]
    public async Task SshConfig_ConnectFailure()
    {
        await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(SshConfigSettings.NoConfig));
    }

    [Fact]
    public async Task SshConfig_HostAuthentication()
    {
        using TempFile configFile = new TempFile(Path.GetTempFileName());
        File.WriteAllText(configFile.Path,
            $"""
            IdentityFile "{_sshServer.TestUserIdentityFile}"
            UserKnownHostsFile {Path.Combine(Path.GetTempPath(), Path.GetRandomFileName())}
            """);
        using var _ = await _sshServer.CreateClientAsync(
            new SshConfigSettings()
            {
                HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    Assert.Equal(KnownHostResult.Unknown, knownHostResult);
                    Assert.Equal(_sshServer.ServerHost, connectionInfo.HostName);
                    Assert.Equal(_sshServer.ServerPort, connectionInfo.Port);
                    Assert.Contains(_sshServer.ServerKeySHA256FingerPrints, key => key == connectionInfo.ServerKey.SHA256FingerPrint);
                    bool isCertificate = _sshServer.ServerKeyCertSHA256FingerPrints.Contains(connectionInfo.ServerKey.CertInfo?.CertificateKey?.SHA256FingerPrint ?? "");
                    Assert.Equal(isCertificate ? _sshServer.CaSHA256FingerPrint : null, connectionInfo.ServerKey.IssuerSHA256FingerPrint);
                    return ValueTask.FromResult(true);
                },
                ConfigFilePaths = [ configFile.Path ]
            }
        );
    }

    [Fact]
    public async Task SshConfig_Options()
    {
        var options = new SshConfigSettings()
        {
            ConfigFilePaths = [],
            Options = new Dictionary<SshConfigOption, SshConfigOptionValue>()
            {
                { SshConfigOption.Hostname, "localhost" },
                { SshConfigOption.User, _sshServer.TestUser },
                { SshConfigOption.Port, _sshServer.ServerPort.ToString() },
                { SshConfigOption.IdentityFile, _sshServer.TestUserIdentityFile },
                { SshConfigOption.StrictHostKeyChecking, "no" },
                { SshConfigOption.UserKnownHostsFile, Path.Combine(Path.GetTempPath(), Path.GetTempFileName()) },
            }
        };
        using var client = new SshClient("dummy", options);
        await client.ConnectAsync();
    }

    [Fact]
    public async Task Disconnected()
    {
        using var client = await _sshServer.CreateClientAsync();

        CancellationToken disconnected = client.Disconnected;

        client.Dispose();

        Assert.True(disconnected.IsCancellationRequested);
    }

    [Fact]
    public async Task Disconnected_WithError()
    {
        using var client = await _sshServer.CreateClientAsync();

        CancellationToken disconnected = client.Disconnected;

        client.ForceConnectionClose();

        Assert.True(disconnected.IsCancellationRequested);
        Assert.True(client.Disconnected.IsCancellationRequested);
    }

    [Fact]
    public async Task Disconnected_RequiresConnect()
    {
        using var client = await _sshServer.CreateClientAsync(connect: false);

        Assert.Throws<InvalidOperationException>(() => client.Disconnected);
    }

    [Fact]
    public async Task Disconnected_NotWhenAutoReconnect()
    {
        using var client = await _sshServer.CreateClientAsync(configure: settings => settings.AutoReconnect = true);

        Assert.Throws<InvalidOperationException>(() => client.Disconnected);
    }

    [Fact]
    public async Task Disconnected_NotAfterDispose()
    {
        using var client = await _sshServer.CreateClientAsync();

        client.Dispose();

        Assert.Throws<ObjectDisposedException>(() => client.Disconnected);
    }
}
