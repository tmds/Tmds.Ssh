using System.Diagnostics;
using System.Security.Cryptography;
using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class CertificateCredentialTests
{
    /*
        The keys and certificates were generated using the following commands.
        The server doesn't know these certificates or their keys.
        It trust the CA, and certificate are issued by the CA for the 'testuser'.

            ssh-keygen -t rsa -N '' -f user_key_2_rsa
            ssh-keygen -s sshd_container/ca -I testuser_rsa -n testuser user_key_2_rsa

            ssh-keygen -t ed25519 -N '' -f user_key_2_ed25519
            ssh-keygen -s sshd_container/ca -I testuser_ed25519 -n testuser user_key_2_ed25519

            ssh-keygen -t ecdsa-sha2-nistp521 -N '' -f user_key_2_ecdsa_nistp521
            ssh-keygen -s sshd_container/ca -I testuser_ecdsa_nistp521 -n testuser user_key_2_ecdsa_nistp521

            ssh-keygen -t ecdsa-sha2-nistp384 -N '' -f user_key_2_ecdsa_nistp384
            ssh-keygen -s sshd_container/ca -I testuser_ecdsa_nistp384 -n testuser user_key_2_ecdsa_nistp384

            ssh-keygen -t ecdsa-sha2-nistp256 -N '' -f user_key_2_ecdsa_nistp256
            ssh-keygen -s sshd_container/ca -I testuser_ecdsa_nistp256 -n testuser user_key_2_ecdsa_nistp256
    */
    private const string ContainerBuildContext = "sshd_container";
    public const string TestUserIdentityFile = $"{ContainerBuildContext}/user_key_2_rsa";
    public const string TestUserIdentityFileEcdsa256 = $"{ContainerBuildContext}/user_key_2_ecdsa_nistp256";
    public const string TestUserIdentityFileEcdsa384 = $"{ContainerBuildContext}/user_key_2_ecdsa_nistp384";
    public const string TestUserIdentityFileEcdsa521 = $"{ContainerBuildContext}/user_key_2_ecdsa_nistp521";
    public const string TestUserIdentityFileEd25519 = $"{ContainerBuildContext}/user_key_2_ed25519";

    private readonly SshServer _sshServer;
    public CertificateCredentialTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [InlineData(TestUserIdentityFile)]
    [InlineData(TestUserIdentityFileEcdsa256)]
    [InlineData(TestUserIdentityFileEcdsa384)]
    [InlineData(TestUserIdentityFileEcdsa521)]
    [InlineData(TestUserIdentityFileEd25519)]
    public async Task Connect(string certIdentityFile)
    {
        using var client = await _sshServer.CreateClientAsync(
            settings => settings.Credentials = [new CertificateCredential($"{certIdentityFile}-cert.pub", new PrivateKeyCredential(certIdentityFile))]
        );
    }

    [Fact]
    public async Task SshConfig_CertificateFile()
    {
        using TempFile configFile = new TempFile(Path.GetTempFileName());
        File.WriteAllText(configFile.Path,
            $"""
            IdentityFile "{TestUserIdentityFile}"
            CertificateFile "{TestUserIdentityFile}-cert.pub"
            UserKnownHostsFile {_sshServer.KnownHostsFilePath}
            """);
        using var _ = await _sshServer.CreateClientAsync(
            new SshConfigSettings()
            {
                ConfigFilePaths = [configFile.Path]
            }
        );
    }
}