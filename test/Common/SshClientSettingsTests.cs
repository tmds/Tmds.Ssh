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
        Assert.Equal(string.Empty, settings.Host);
        Assert.Equal(22, settings.Port);
        Assert.Equal(SshClientSettings.DefaultCredentials, settings.Credentials);
        Assert.Equal(DefaultKnownHostsFile, settings.KnownHostsFilePath);
        Assert.True(settings.CheckGlobalKnownHostsFile);
        Assert.Null(settings.KeyVerification);
    }

    private static string DefaultKnownHostsFile
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify),
                        ".ssh",
                        "known_hosts");
}
