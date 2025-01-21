using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class HostKeyAlgorithmTests
{
    private readonly SshServer _sshServer;

    public HostKeyAlgorithmTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task ConnectWithHostKeyAlgorithm(string algorithm)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings => settings.ServerHostKeyAlgorithms = [ new Name(algorithm) ]
        );
    }

    public static IEnumerable<object[]> Algorithms =>
        SshClientSettings.SupportedServerHostKeyAlgorithms.Select(algorithm => new object[] { algorithm.ToString() });
}
