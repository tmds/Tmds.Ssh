using Xunit;
using static System.Environment;

namespace Tmds.Ssh.Tests;

public class ClientSettingsTests
{
    [Fact]
    public void Defaults()
    {
        var settings = new SshClientSettings();
        Assert.Equal(TimeSpan.FromSeconds(15), settings.ConnectTimeout);
        Assert.Equal(22, settings.Port);
        Assert.Equal(2048, settings.MinimumRSAKeySize);
        Assert.Equal(Environment.UserName, settings.UserName);
        Assert.Equal(string.Empty, settings.HostName);
        Assert.Equal(SshClientSettings.DefaultCredentials, settings.Credentials);
        Assert.False(settings.UpdateKnownHostsFileAfterAuthentication);
        Assert.True(settings.AutoConnect);
        Assert.False(settings.AutoReconnect);
        Assert.Equal(new[] { DefaultKnownHostsFile }, settings.UserKnownHostsFilePaths);
        Assert.Equal(new[] { DefaultGlobalKnownHostsFile }, settings.GlobalKnownHostsFilePaths);
        Assert.Null(settings.HostAuthentication);
        Assert.Equal(new[] { new Name("sntrup761x25519-sha512"), new Name("sntrup761x25519-sha512@openssh.com"), new Name("curve25519-sha256"), new Name("curve25519-sha256@libssh.org"), new Name("ecdh-sha2-nistp256"), new Name("ecdh-sha2-nistp384"), new Name("ecdh-sha2-nistp521") }, settings.KeyExchangeAlgorithms);
        Assert.Equal(new[] { new Name("ssh-ed25519"), new Name("ecdsa-sha2-nistp521"), new Name("ecdsa-sha2-nistp384"), new Name("ecdsa-sha2-nistp256"), new Name("rsa-sha2-512"), new Name("rsa-sha2-256") }, settings.ServerHostKeyAlgorithms);
        Assert.Null(settings.PublicKeyAcceptedAlgorithms);
        Assert.Equal(new[] { new Name("ssh-ed25519"), new Name("ecdsa-sha2-nistp521"), new Name("ecdsa-sha2-nistp384"), new Name("ecdsa-sha2-nistp256"), new Name("rsa-sha2-512"), new Name("rsa-sha2-256") }, SshClientSettings.SupportedPublicKeyAlgorithms);
        Assert.Equal(new[] { new Name("aes256-gcm@openssh.com"), new Name("aes128-gcm@openssh.com"), new Name("chacha20-poly1305@openssh.com") }, settings.EncryptionAlgorithmsClientToServer);
        Assert.Equal(new[] { new Name("aes256-gcm@openssh.com"), new Name("aes128-gcm@openssh.com"), new Name("chacha20-poly1305@openssh.com") }, settings.EncryptionAlgorithmsServerToClient);
        Assert.Equal(Array.Empty<Name>(), settings.MacAlgorithmsClientToServer);
        Assert.Equal(Array.Empty<Name>(), settings.MacAlgorithmsServerToClient);
        Assert.Equal(new[] { new Name("none") }, settings.CompressionAlgorithmsClientToServer);
        Assert.Equal(new[] { new Name("none") }, settings.CompressionAlgorithmsServerToClient);
        Assert.Equal(Array.Empty<Name>(), settings.LanguagesClientToServer);
        Assert.Equal(Array.Empty<Name>(), settings.LanguagesServerToClient);
        Assert.Equal(3, settings.KeepAliveCountMax);
        Assert.Equal(TimeSpan.Zero, settings.KeepAliveInterval);
    }

    [Theory]
    [InlineData("", null, "", 22)]
    [InlineData("host.com", null, "host.com", 22)]
    [InlineData("user@host.com", "user", "host.com", 22)]
    [InlineData("host.com:5000", null, "host.com", 5000)]
    [InlineData("user@host.com:5000", "user", "host.com", 5000)]
    [InlineData("user@realm@host.com", "user@realm", "host.com", 22)]
    [InlineData("user@realm@host.com:5000", "user@realm", "host.com", 5000)]
    public void Parse(string destination, string? expectedUsername, string expectedHost, int expectedPort)
    {
        expectedUsername ??= Environment.UserName;

        var settings = new SshClientSettings(destination);

        Assert.Equal(expectedHost, settings.HostName);
        Assert.Equal(expectedUsername, settings.UserName);
        Assert.Equal(expectedPort, settings.Port);
    }

    private static string DefaultKnownHostsFile
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify),
                        ".ssh",
                        "known_hosts");

    private static string DefaultGlobalKnownHostsFile
        => OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(SpecialFolder.CommonApplicationData, SpecialFolderOption.DoNotVerify), "ssh", "known_hosts")
        : "/etc/ssh/known_hosts";
}
