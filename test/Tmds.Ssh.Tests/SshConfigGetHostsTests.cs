using Xunit;

namespace Tmds.Ssh.Tests;

public class SshConfigGetHostsTests
{
    [Fact]
    public void GetHosts_SingleHost()
    {
        using TempFile file = CreateConfigFile("""
            Host myserver
                HostName 192.168.1.1
            """);

        var hosts = SshConfig.GetHosts([file.Path]);

        Assert.Equal(new HashSet<string> { "myserver" }, hosts);
    }

    [Fact]
    public void GetHosts_MultipleHosts()
    {
        using TempFile file = CreateConfigFile("""
            Host server1
                HostName 192.168.1.1

            Host server2
                HostName 192.168.1.2
            """);

        var hosts = SshConfig.GetHosts([file.Path]);

        Assert.Equal(new HashSet<string> { "server1", "server2" }, hosts);
    }

    [Fact]
    public void GetHosts_WildcardsFilteredOut()
    {
        using TempFile file = CreateConfigFile("""
            Host myserver
                HostName 192.168.1.1

            Host *.example.com
                User admin

            Host server?
                Port 22

            Host *
                ServerAliveInterval 60
            """);

        var hosts = SshConfig.GetHosts([file.Path]);

        Assert.Equal(new HashSet<string> { "myserver" }, hosts);
    }

    [Fact]
    public void GetHosts_NegationFilteredOut()
    {
        using TempFile file = CreateConfigFile("""
            Host myserver !badhost
                HostName 192.168.1.1
            """);

        var hosts = SshConfig.GetHosts([file.Path]);

        Assert.Equal(new HashSet<string> { "myserver" }, hosts);
    }

    [Fact]
    public void GetHosts_EmptyFile()
    {
        using TempFile file = CreateConfigFile("");

        var hosts = SshConfig.GetHosts([file.Path]);

        Assert.Empty(hosts);
    }

    [Fact]
    public void GetHosts_NonExistentFile()
    {
        var hosts = SshConfig.GetHosts(["/tmp/nonexistent_ssh_config_test"]);

        Assert.Empty(hosts);
    }

    [Fact]
    public void GetHosts_FollowsInclude()
    {
        using TempFile included = CreateConfigFile("""
            Host includedserver
                HostName 10.0.0.1
            """);

        using TempFile main = CreateConfigFile($"""
            Include {included.Path}

            Host mainserver
                HostName 10.0.0.2
            """);

        var hosts = SshConfig.GetHosts([main.Path]);

        Assert.Equal(new HashSet<string> { "includedserver", "mainserver" }, hosts);
    }

    [Fact]
    public void GetHosts_Deduplicated()
    {
        using TempFile file = CreateConfigFile("""
            Host myserver
                HostName 192.168.1.1

            Host myserver
                Port 2222
            """);

        var hosts = SshConfig.GetHosts([file.Path]);

        Assert.Single(hosts);
        Assert.Contains("myserver", hosts);
    }

    [Fact]
    public void GetHosts_MultipleHostsOnOneLine()
    {
        using TempFile file = CreateConfigFile("""
            Host server1 server2 server3
                HostName 192.168.1.1
            """);

        var hosts = SshConfig.GetHosts([file.Path]);

        Assert.Equal(new HashSet<string> { "server1", "server2", "server3" }, hosts);
    }

    [Fact]
    public void GetHosts_MultipleConfigFiles()
    {
        using TempFile file1 = CreateConfigFile("""
            Host server1
                HostName 10.0.0.1
            """);

        using TempFile file2 = CreateConfigFile("""
            Host server2
                HostName 10.0.0.2
            """);

        var hosts = SshConfig.GetHosts([file1.Path, file2.Path]);

        Assert.Equal(new HashSet<string> { "server1", "server2" }, hosts);
    }

    [Fact]
    public void GetHosts_MultipleConfigFilesDeduplicatedAcrossFiles()
    {
        using TempFile file1 = CreateConfigFile("""
            Host myserver
                HostName 10.0.0.1
            """);

        using TempFile file2 = CreateConfigFile("""
            Host myserver
                HostName 10.0.0.2
            """);

        var hosts = SshConfig.GetHosts([file1.Path, file2.Path]);

        Assert.Single(hosts);
        Assert.Contains("myserver", hosts);
    }

    private static TempFile CreateConfigFile(string content)
    {
        string path = Path.GetTempFileName();
        File.WriteAllText(path, content);
        return new TempFile(path);
    }
}
