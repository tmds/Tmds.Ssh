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
        SshClientSettings.SupportedKeyExchangeAlgorithms
        .Select(algorithm => algorithm.ToString())
        .Where(algorithm => algorithm != "mlkem768x25519-sha256") // https://github.com/tmds/Tmds.Ssh/issues/398
        .Select(algorithm => new object[] { algorithm });

    public static bool IsCi => Environment.GetEnvironmentVariable("IS_CI") == "1";
}
