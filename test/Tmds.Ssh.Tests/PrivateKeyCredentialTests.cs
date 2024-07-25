using Xunit;

using System.Threading.Tasks;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class PrivateKeyCredentialTests
{
    private readonly SshServer _sshServer;

    public PrivateKeyCredentialTests(SshServer sshServer) : base()
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task OpenSshRsa()
    {
        await ConnectWithKey(_sshServer.TestUserIdentityFile);
    }

    [Fact]
    public async Task OpenSshEcdsa256()
    {
        await ConnectWithKey(_sshServer.TestUserIdentityFileEcdsa256);
    }

    [Fact]
    public async Task OpenSshEcdsa384()
    {
        await ConnectWithKey(_sshServer.TestUserIdentityFileEcdsa384);
    }

    [Fact]
    public async Task OpenSshEcdsa521()
    {
        await ConnectWithKey(_sshServer.TestUserIdentityFileEcdsa521);
    }

    private async Task ConnectWithKey(string keyPath)
    {
        var settings = new SshClientSettings(_sshServer.Destination)
        {
            KnownHostsFilePath = _sshServer.KnownHostsFilePath,
            Credentials = [ new PrivateKeyCredential(keyPath) ],
        };
        using var client = new SshClient(settings);

        await client.ConnectAsync();
    }
}
