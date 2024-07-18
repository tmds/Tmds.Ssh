using System;
using System.IO;
using Xunit;

namespace Tmds.Ssh.Tests;

public class ClientSettingsTests
{
    [Fact]
    public void Defaults()
    {
        var settings = new SshClientSettings();
        Assert.Equal(TimeSpan.FromSeconds(15), settings.ConnectTimeout);
        Assert.Equal(string.Empty, settings.UserName);
        Assert.Equal(string.Empty, settings.HostName);
        Assert.Equal(22, settings.Port);
        Assert.Equal(SshClientSettings.DefaultCredentials, settings.Credentials);
        Assert.Null(settings.HostAuthentication);
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
}
