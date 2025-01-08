using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class SshProxyTests
{
    private readonly SshServer _sshServer;

    public SshProxyTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SshProxyWithSshClientSettings(bool withProxy)
    {
        var sshProxySettings = new SshClientSettings(_sshServer.Destination)
        {
            Credentials = [ new PrivateKeyCredential(_sshServer.TestUserIdentityFile) ],
            HostAuthentication =
            async (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
            {
                Assert.Equal(_sshServer.ServerHost, connectionInfo.HostName);
                Assert.True(connectionInfo.IsProxy);
                return true;
            }
        };
        NoopProxy noopProxy = new NoopProxy();
        if (withProxy)
        {
            sshProxySettings.Proxy = noopProxy;
        }

        using var client = await _sshServer.CreateClientAsync(settings =>
        {
            settings.HostName = "localhost";
            settings.Port = 22;
            settings.Proxy = new SshProxy(sshProxySettings);
            settings.HostAuthentication =
                async (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    Assert.Equal("localhost", connectionInfo.HostName);
                    Assert.False(connectionInfo.IsProxy);
                    return true;
                };
        });

        Assert.Equal(withProxy, noopProxy.IsUsed);
    }

    [Fact]
    public async Task SshProxyWithSshConfig()
    {
        var sshConfig = new SshConfigSettings()
        {
            ConfigFilePaths = [ _sshServer.SshConfigFilePath ]
        };

        using var client = await _sshServer.CreateClientAsync(settings =>
        {
            settings.HostName = "localhost";
            settings.Port = 22;
            settings.Proxy = new SshProxy(_sshServer.Destination, sshConfig);
            settings.HostAuthentication =
                async (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    Assert.Equal("localhost", connectionInfo.HostName);
                    Assert.False(connectionInfo.IsProxy);
                    return true;
                };
        });
    }

    sealed class NoopProxy : Proxy
    {
        public bool IsUsed { get; set; }

        internal override ValueTask<Stream> ConnectToProxyAndForward(ConnectCallback connect, ConnectContext context, CancellationToken ct)
        {
            IsUsed = true;
            return connect(context, ct);
        }
    }
}
