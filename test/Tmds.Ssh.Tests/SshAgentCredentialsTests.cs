using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class SshAgentCredentialsTests
{
    private readonly SshServer _sshServer;

    public SshAgentCredentialsTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task Success()
    {
        using var agent = new LocalSshAgent();
        agent.Start();
        agent.Add(_sshServer.TestUserIdentityFile);

        var settings = new SshClientSettings(_sshServer.Destination)
        {
            UserKnownHostsFilePaths = [ _sshServer.KnownHostsFilePath ],
            Credentials = [ new SshAgentCredentials(agent.Address) ]
        };
        using var client = new SshClient(settings);
        await client.ConnectAsync();
    }
}
