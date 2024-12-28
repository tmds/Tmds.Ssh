using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class KeyExchangeAlgorithmTests
{
    private readonly SshServer _sshServer;

    public KeyExchangeAlgorithmTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task ConnectWithKeyExchangeAlgorithm(string algorithm)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings => settings.KeyExchangeAlgorithms = [new Name(algorithm)]
        );
    }

    public static IEnumerable<object[]> Algorithms =>
        SshClientSettings.SupportedKeyExchangeAlgorithms.Select(algorithm => new object[] { algorithm.ToString() });
}
