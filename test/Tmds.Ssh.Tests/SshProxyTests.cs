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
            (HostAuthenticationContext context, CancellationToken cancellationToken) =>
            {
                Assert.Equal(_sshServer.ServerHost, context.ConnectionInfo.HostName);
                Assert.True(context.ConnectionInfo.IsProxy);
                return ValueTask.FromResult(true);
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
                (HostAuthenticationContext context, CancellationToken cancellationToken) =>
                {
                    Assert.Equal("localhost", context.ConnectionInfo.HostName);
                    Assert.False(context.ConnectionInfo.IsProxy);
                    return ValueTask.FromResult(true);
                };
        });

        Assert.Equal(withProxy, noopProxy.IsUsed);
    }

    [Fact]
    public async Task SshProxyWithSshClientSettingsFromDestination()
    {
        using var client = await _sshServer.CreateClientAsync(
        new SshClientSettings()
        {
            HostName = "localhost",
            UserName = _sshServer.TestUser,
            Port = 22,

            Proxy = new SshProxy(_sshServer.Destination),

            Credentials = [ new PrivateKeyCredential(_sshServer.TestUserIdentityFile) ],

            UserKnownHostsFilePaths = [],
            HostAuthentication =
            (HostAuthenticationContext context, CancellationToken cancellationToken) =>
            {
                if (context.ConnectionInfo.HostName == _sshServer.ServerHost)
                {
                    Assert.True(context.ConnectionInfo.IsProxy);
                }
                else
                {
                    Assert.Equal("localhost", context.ConnectionInfo.HostName);
                    Assert.False(context.ConnectionInfo.IsProxy);
                }
                return ValueTask.FromResult(true);
            }
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
