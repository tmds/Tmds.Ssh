using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(MultiMethodAuthSshServerCollection))]
public class MultiMethodAuthenticationTests
{
    private readonly MultiMethodAuthSshServer _sshServer;

    public MultiMethodAuthenticationTests(MultiMethodAuthSshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task Success()
    {
        var settings = new SshClientSettings(_sshServer.Destination)
        {
            UserKnownHostsFilePaths = [ _sshServer.KnownHostsFilePath ],
            Credentials = [ _sshServer.FirstCredential, _sshServer.SecondCredential ]
        };
        using var client = new SshClient(settings);

        await client.ConnectAsync();
    }

    [Fact]
    public async Task OutOfOrderSuccess()
    {
        var settings = new SshClientSettings(_sshServer.Destination)
        {
            UserKnownHostsFilePaths = [ _sshServer.KnownHostsFilePath ],
            Credentials = [ _sshServer.SecondCredential, _sshServer.FirstCredential ]
        };
        using var client = new SshClient(settings);

        await client.ConnectAsync();
    }

    [Fact]
    public async Task FailureCredentialSuccess()
    {
        Credential incorrectPassword = new PasswordCredential("incorrect");
        var settings = new SshClientSettings(_sshServer.Destination)
        {
            UserKnownHostsFilePaths = [ _sshServer.KnownHostsFilePath ],
            Credentials = [ incorrectPassword, _sshServer.FirstCredential, _sshServer.SecondCredential ]
        };
        using var client = new SshClient(settings);

        await client.ConnectAsync();
    }

    [Fact]
    public async Task ServerConfiguredForMultiAuth()
    {
        var settings = new SshClientSettings(_sshServer.Destination)
        {
            UserKnownHostsFilePaths = [ _sshServer.KnownHostsFilePath ],
            Credentials = [ _sshServer.FirstCredential ]
        };
        using var client = new SshClient(settings);

        await Assert.ThrowsAsync<ConnectFailedException>(() => client.ConnectAsync());
    }
}
