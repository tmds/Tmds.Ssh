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
                settings.KnownHostsFilePath = "/"
            ));
    }

    [Fact]
    public async Task KeyVerificationHasConnectionInfo()
    {
        using var _ = await _sshServer.CreateClientAsync(settings =>
            {
                settings.KnownHostsFilePath = "/";
                settings.HostAuthentication =
                (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    Assert.Equal(KnownHostResult.Unknown, knownHostResult);
                    Assert.Equal(_sshServer.ServerHost, connectionInfo.Host);
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
                settings.KnownHostsFilePath = null;
                settings.CheckGlobalKnownHostsFile = false;
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
                settings.KnownHostsFilePath = "/";
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
                    settings.KnownHostsFilePath = knownHostsFileName;
                    settings.HostAuthentication =
                    (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                    {
                        keyVerified = true;
                        Assert.Equal(KnownHostResult.Unknown, knownHostResult);
                        return ValueTask.FromResult(true);
                    };
                    settings.UpdateKnownHostsFile = true;
                });
            client.Dispose();
            Assert.True(keyVerified);
            Assert.True(File.Exists(knownHostsFileName));

            client = await _sshServer.CreateClientAsync(settings =>
            {
                settings.KnownHostsFilePath = knownHostsFileName;
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

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task AddKnownHostDoesNotErrorWithEmptyPath(string? path)
    {
        using SshClient client = await _sshServer.CreateClientAsync(settings =>
        {
            settings.KnownHostsFilePath = path;
            settings.HostAuthentication =
            (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
            {
                return ValueTask.FromResult(true);
            };
            settings.UpdateKnownHostsFile = true;
        });
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
            KnownHostsFilePath = _sshServer.KnownHostsFilePath,
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

        using var client = new SshClient($"user@{address}:{port}");

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
                settings.KnownHostsFilePath = "/";
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
                settings.KnownHostsFilePath = "/";
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
                settings.KnownHostsFilePath = "/";
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
}
