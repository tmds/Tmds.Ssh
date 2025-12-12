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
            settings => settings.ServerHostKeyAlgorithms = [ algorithm ]
        );
    }

    [Theory]
    [MemberData(nameof(CertificateAlgorithms))]
    public async Task ConnectWithHostKeyAlgorithmCertificateAuth(string algorithm)
    {
        string hostPattern = $"[{_sshServer.ServerHost}]:{_sshServer.ServerPort}";
        using TempFile knownHostsFile = new TempFile(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()));
        File.WriteAllText(knownHostsFile.Path, $"@cert-authority {hostPattern} {File.ReadAllText(_sshServer.CAPubFile).Trim()}");
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.ServerHostKeyAlgorithms = [ algorithm ];
                settings.UserKnownHostsFilePaths = [ knownHostsFile.Path ];
            }
        );
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task ConnectWithHostKeyAlgorithmSkipsUnknown(string algorithm)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings => settings.ServerHostKeyAlgorithms = [ "dummy-algorithm", algorithm ]
        );
    }

    [Fact]
    public async Task ConnectWithHostKeyAlgorithmFailsWhenNoSupported()
    {
        await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(
                settings => settings.ServerHostKeyAlgorithms = [ "dummy-algorithm" ]
            ));
    }

    public static IEnumerable<object[]> Algorithms =>
        SshClientSettings.SupportedServerHostKeyAlgorithms.Select(algorithm => new object[] { algorithm.ToString() });

    public static IEnumerable<object[]> CertificateAlgorithms =>
        SshClientSettings.SupportedServerHostKeyAlgorithms.Where(name => name.EndsWith(AlgorithmNames.CertSuffix)).Select(algorithm => new object[] { algorithm.ToString() });
}
