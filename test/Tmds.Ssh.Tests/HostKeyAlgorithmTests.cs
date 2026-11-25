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
        string caKeys = string.Join("\n",
            $"@cert-authority {hostPattern} {File.ReadAllText(_sshServer.CAPubFile).Trim()}",
            $"@cert-authority {hostPattern} {File.ReadAllText(_sshServer.CAEd25519PubFile).Trim()}",
            $"@cert-authority {hostPattern} {File.ReadAllText(_sshServer.CAEcdsaPubFile).Trim()}",
            $"@cert-authority {hostPattern} {File.ReadAllText(_sshServer.CAMlDsa44Ed25519PubFile).Trim()}");
        File.WriteAllText(knownHostsFile.Path, caKeys);
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.ServerHostKeyAlgorithms = [ algorithm ];
                settings.UserKnownHostsFilePaths = [ knownHostsFile.Path ];
            }
        );
    }

    [Theory]
    [MemberData(nameof(CertificateAuthorities))]
    public async Task ConnectWithCertificateAuthority(string caFile, string certAlgorithm)
    {
        string hostPattern = $"[{_sshServer.ServerHost}]:{_sshServer.ServerPort}";
        using TempFile knownHostsFile = new TempFile(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()));
        File.WriteAllText(knownHostsFile.Path, $"@cert-authority {hostPattern} {File.ReadAllText(caFile).Trim()}");
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.ServerHostKeyAlgorithms = [ certAlgorithm ];
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
        SshClientSettings.SupportedServerHostKeyAlgorithms.Where(name => AlgorithmNames.IsCertAlgorithm(name)).Select(algorithm => new object[] { algorithm.ToString() });

    public static IEnumerable<object[]> CertificateAuthorities =>
        new[]
        {
            new object[] { "sshd_container/ca.pub", "ecdsa-sha2-nistp256-cert-v01@openssh.com" },
            new object[] { "sshd_container/ca.pub", "ssh-mldsa44-ed25519-cert" },
            new object[] { "sshd_container/ca_ed25519.pub", "ecdsa-sha2-nistp384-cert-v01@openssh.com" },
            new object[] { "sshd_container/ca_ecdsa.pub", "ecdsa-sha2-nistp521-cert-v01@openssh.com" },
            new object[] { "sshd_container/ca_mldsa44_ed25519.pub", "ssh-ed25519-cert-v01@openssh.com" },
        };
}
