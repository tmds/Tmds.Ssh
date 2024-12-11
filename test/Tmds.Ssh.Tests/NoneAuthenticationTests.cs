using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(NoneAuthSshServerCollection))]
public class NoneAuthenticationTests
{
    private readonly NoneAuthSshServer _sshServer;

    public NoneAuthenticationTests(NoneAuthSshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task Success()
    {
        var settings = new SshClientSettings(_sshServer.Destination)
        {
            UserKnownHostsFilePaths = [ _sshServer.KnownHostsFilePath ],
            Credentials = [ new NoCredential() ]
        };

        using var client = new SshClient(settings);

        await client.ConnectAsync();
    }
}
