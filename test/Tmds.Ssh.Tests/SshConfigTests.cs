using Xunit;

namespace Tmds.Ssh.Tests;

public class SshConfigTests
{
    private static readonly string Home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);

    // Config that sets all understood settings.
    private const string SupportedSettingsConfig =
    """
    HostName hostname
    User username
    Port 3000
    ConnectTimeout 500
    GlobalKnownHostsFile /global1 /global2
    UserKnownHostsFile /user1 /user2
    PreferredAuthentications auth1,auth2
    PubKeyAuthentication no
    IdentityFile /identity1
    IdentityFile /identity2
    GssApiAuthentication yes
    GssApiDelegateCredentials yes
    GssApiServerIdentity serverid
    RequiredRSASize 8000
    Ciphers aes256-ctr,aes256-gcm@openssh.com
    Compression yes
    HostKeyAlgorithms ecdsa-sha2-nistp521,ssh-ed25519-cert-v01@openssh.com
    KexAlgorithms curve25519-sha256,ecdh-sha2-nistp384
    Macs hmac-sha2-256-etm@openssh.com,hmac-sha2-512
    PubKeyAcceptedAlgorithms rsa-sha2-256,ecdsa-sha2-nistp256
    CanonicalizeHostName no
    ServerAliveCountMax 7
    ServerAliveInterval 20

    # !!! update SupportedSettingsAlternateConfig when adding values here !!!
    """;

    // Alternative values for options set in SupportedSettingsConfig.
    private const string SupportedSettingsAlternateConfig =
    """
    HostName hostname2
    User username2
    Port 4000
    ConnectTimeout 600
    GlobalKnownHostsFile /global3 /global4
    UserKnownHostsFile /user3 /user4
    PreferredAuthentications auth3,auth4
    # skip IdentityFile because it is additive.
    PubKeyAuthentication yes
    GssApiAuthentication no
    GssApiDelegateCredentials no
    GssApiServerIdentity serverid2
    RequiredRSASize 16000
    Ciphers aes256-gcm@openssh.com
    Compression no
    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com
    KexAlgorithms ecdh-sha2-nistp384
    Macs hmac-sha2-512
    PubKeyAcceptedAlgorithms ecdsa-sha2-nistp256
    CanonicalizeHostName yes
    ServerAliveCountMax 8
    ServerAliveInterval 30
    """;

    [Fact]
    public async Task SupportedSettings()
    {
        SshConfig config = await DetermineConfigAsync(SupportedSettingsConfig);

        VerifyConfig(config);
    }

    [Fact]
    public async Task SettingsAreNotOverridden()
    {
        // This test verifies the values of SupportedSettingsConfig
        // are not overridden by the values of SupportedSettingsAlternateConfig.
        const string Config =
        $"""
        {SupportedSettingsConfig}
        {SupportedSettingsAlternateConfig}
        """;
        SshConfig config = await DetermineConfigAsync(Config);

        VerifyConfig(config);
    }

    private void VerifyConfig(SshConfig config)
    {
        Assert.Equal("hostname", config.HostName);
        Assert.Equal("username", config.UserName);
        Assert.Equal(3000, config.Port);
        Assert.Equal(500, config.ConnectTimeout);
        Assert.Equal(new[] { "/global1", "/global2" }, config.GlobalKnownHostsFiles);
        Assert.Equal(new[] { "/user1", "/user2" }, config.UserKnownHostsFiles);
        Assert.Equal(new[] { "/identity1", "/identity2" }, config.IdentityFiles);
        Assert.Equal(new[] { new Name("aes256-ctr"), new Name("aes256-gcm@openssh.com")}, config.Ciphers!.Value.Algorithms);
        Assert.Equal(new[] { new Name("ecdsa-sha2-nistp521"), new Name("ssh-ed25519-cert-v01@openssh.com") }, config.HostKeyAlgorithms!.Value.Algorithms);
        Assert.Equal(new[] { new Name("curve25519-sha256"), new Name("ecdh-sha2-nistp384") }, config.KexAlgorithms!.Value.Algorithms);
        Assert.Equal(new[] { new Name("hmac-sha2-256-etm@openssh.com"), new Name("hmac-sha2-512") }, config.Macs!.Value.Algorithms);
        Assert.Equal("rsa-sha2-256,ecdsa-sha2-nistp256", config.PublicKeyAcceptedAlgorithms!.Value.PatternList);
        Assert.Equal(new[] { new Name("auth1"), new Name("auth2") }, config.PreferredAuthentications);
        Assert.Equal(8000, config.RequiredRSASize);
        Assert.Equal(true, config.Compression);
        Assert.Equal(false, config.PubKeyAuthentication);
        Assert.Equal(true, config.GssApiAuthentication);
        Assert.Equal(true, config.GssApiDelegateCredentials);
        Assert.Equal("serverid", config.GssApiServerIdentity);
        Assert.Equal(7, config.ServerAliveCountMax);
        Assert.Equal(20, config.ServerAliveInterval);
    }

    [Fact]
    public async Task HostMatching()
    {
        const string HostMatchConfig =
        """
        # Exact match with hostname
        Host foo.bar
        Port 3000

        # Pattern match with hostname
        Host *.bar
        ConnectTimeout 5000

        # Negate
        Host foo.bar !*
        RequiredRSASize 6000

        # Match all
        Host *
        RequiredRSASize 2000
        """;


        SshConfig config = await DetermineConfigAsync(HostMatchConfig, host: "foo.bar");

        Assert.Equal(3000, config.Port);
        Assert.Equal(5000, config.ConnectTimeout);
        Assert.Equal(2000, config.RequiredRSASize);
    }

    [Fact]
    public async Task MatchMatching()
    {
        const string Host = "foo.bar";
        const string HostName = "foo3.bar";
        const string OtherHost = "foo2.bar";
        const string User = "alice";
        const string OtherUser = "bob";

        const string MatchConfig =
        $"""
        # Match on the second pass
        Match final host {HostName}
        Port 3000

        # Match all
        Match all
        HostName {HostName}

        # No match
        Match host {OtherHost}
        ConnectTimeout 2000

        # No match: match host but not user
        Match host {HostName} user {OtherUser}
        ConnectTimeout 3000

        # Match host and user
        Match host {HostName} user {User}
        ConnectTimeout 4000

        # Match: negate
        Match !host {OtherHost}
        RequiredRSASize 6000

        # No Match: negate pattern
        Match host !{OtherHost}
        PubKeyAuthentication yes

        # Match: wildcard and negate
        Match host *,!{OtherHost}
        GssApiAuthentication yes
        """;

        SshConfig config = await DetermineConfigAsync(MatchConfig, username: User, host: Host);

        Assert.Equal(3000, config.Port);
        Assert.Equal(4000, config.ConnectTimeout);
        Assert.Equal(6000, config.RequiredRSASize);
        Assert.Null(config.PubKeyAuthentication);
        Assert.Equal(true, config.GssApiAuthentication);
    }

    [Fact]
    public async Task Include()
    {
        // Include file from home
        const string IncludedFromHomeConfig =
        """
        ConnectTimeout 2000
        """;
        string homeFileName = Path.GetRandomFileName();
        using TempFile homeFilePath = new TempFile(Path.Combine(Home, homeFileName));
        File.WriteAllText(homeFilePath.Path, IncludedFromHomeConfig);

        string configDir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName())).FullName;
        try
        {
            Directory.CreateDirectory(Path.Combine(configDir, "subdir"));
            const string Include1Config =
            """
            # Note: this path will be interpreted relative to the configFile directory (and not to this config file's parent directory).
            Include subdir/include2
            """;
            File.WriteAllText(Path.Combine(configDir, "subdir", "include1"), Include1Config);
            const string Include2Config =
            """
            RequiredRSASize 6000
            """;
            File.WriteAllText(Path.Combine(configDir, "subdir", "include2"), Include2Config);

            Directory.CreateDirectory(Path.Combine(configDir, "globdir"));
            const string GlobbedConfig =
            """
            GssApiAuthentication yes
            """;
            File.WriteAllText(Path.Combine(configDir, "globdir", "config"), GlobbedConfig);

            string IncludeConfig =
            $"""
            # Home directory include
            Include ~/{homeFileName}
            # Relative include
            Include subdir/include1
            # Glob
            Include globdir/*
            """;

            string configFile = Path.Combine(configDir, "ssh_config");
            File.WriteAllText(configFile, IncludeConfig);
            SshConfig config = await SshConfig.DetermineConfigForHost(userName: null, host: "", port: null, new Dictionary<SshConfigOption, SshConfigOptionValue>(), [configFile], cancellationToken: default);

            Assert.Equal(2000, config.ConnectTimeout);
            Assert.Equal(6000, config.RequiredRSASize);
            Assert.Equal(true, config.GssApiAuthentication);
        }
        finally
        {
            try
            {
                Directory.Delete(configDir, recursive: true);
            }
            catch
            { }
        }
    }

    [Fact]
    public async Task AlgorithmParsing()
    {
        const string Config =
        $"""
        Ciphers cipher1,cipher2
        HostKeyAlgorithms +alg1,alg2
        KexAlgorithms -kex1,kex2
        Macs ^mac1,mac2
        PubKeyAcceptedAlgorithms pubkey1,pubkey2*
        """;

        SshConfig config = await DetermineConfigAsync(Config);

        Assert.Equal(SshConfig.AlgorithmListOperation.Set, config.Ciphers!.Value.Operation);
        Assert.Equal(new[] { new Name("cipher1"), new Name("cipher2")}, config.Ciphers!.Value.Algorithms);

        Assert.Equal(SshConfig.AlgorithmListOperation.Append, config.HostKeyAlgorithms!.Value.Operation);
        Assert.Equal(new[] { new Name("alg1"), new Name("alg2")}, config.HostKeyAlgorithms!.Value.Algorithms);

        Assert.Equal(SshConfig.AlgorithmListOperation.Remove, config.KexAlgorithms!.Value.Operation);
        Assert.Equal("kex1,kex2", config.KexAlgorithms!.Value.PatternList);

        Assert.Equal(SshConfig.AlgorithmListOperation.Prepend, config.Macs!.Value.Operation);
        Assert.Equal(new[] { new Name("mac1"), new Name("mac2")}, config.Macs!.Value.Algorithms);

        Assert.Equal(SshConfig.AlgorithmListOperation.Filter, config.PublicKeyAcceptedAlgorithms!.Value.Operation);
        Assert.Equal("pubkey1,pubkey2*", config.PublicKeyAcceptedAlgorithms!.Value.PatternList);
    }

    [Fact]
    public void DetermineAlgorithms_Prepend()
    {
        SshConfig.AlgorithmList list = new()
        {
            Algorithms = new[] { new Name("alg1"), new Name("alg2"), new Name("unsupported")},
            Operation = SshConfig.AlgorithmListOperation.Prepend,
            PatternList = ""
        };

        List<Name> defaultAlgorithms = [ new Name("alg3"), new Name("alg2") ];
        List<Name> supportedAlgorithms = [ new Name("alg1"), new Name("alg2"), new Name("alg3") ];

        List<Name> algorithms = SshClientSettings.DetermineAlgorithms(list, defaultAlgorithms, supportedAlgorithms);

        Assert.Equal(new[] { new Name("alg1"), new Name("alg2"), new Name("alg3")}, algorithms);
    }

    [Fact]
    public void DetermineAlgorithms_Append()
    {
        SshConfig.AlgorithmList list = new()
        {
            Algorithms = new[] { new Name("alg1"), new Name("alg2"), new Name("unsupported")},
            Operation = SshConfig.AlgorithmListOperation.Append,
            PatternList = ""
        };

        List<Name> defaultAlgorithms = [ new Name("alg3"), new Name("alg2") ];
        List<Name> supportedAlgorithms = [ new Name("alg1"), new Name("alg2"), new Name("alg3")];

        List<Name> algorithms = SshClientSettings.DetermineAlgorithms(list, defaultAlgorithms, supportedAlgorithms);

        Assert.Equal(new[] { new Name("alg3"), new Name("alg2"), new Name("alg1")}, algorithms);
    }

    [Fact]
    public void DetermineAlgorithms_Remove()
    {
        SshConfig.AlgorithmList list = new()
        {
            Algorithms = Array.Empty<Name>(),
            Operation = SshConfig.AlgorithmListOperation.Remove,
            PatternList = "alg3,alg4"
        };

        List<Name> defaultAlgorithms = [ new Name("alg3"), new Name("alg2") ];
        List<Name> supportedAlgorithms = [ new Name("alg1"), new Name("alg2"), new Name("alg3"), new Name("alg4") ];

        List<Name> algorithms = SshClientSettings.DetermineAlgorithms(list, defaultAlgorithms, supportedAlgorithms);

        Assert.Equal(new[] { new Name("alg2") }, algorithms);
    }

    [Fact]
    public void DetermineAlgorithms_Filter()
    {
        SshConfig.AlgorithmList list = new()
        {
            Algorithms = Array.Empty<Name>(),
            Operation = SshConfig.AlgorithmListOperation.Filter,
            PatternList = "alg3,alg4"
        };

        List<Name> defaultAlgorithms = [ new Name("alg3"), new Name("alg2") ];
        List<Name> supportedAlgorithms = [ new Name("alg1"), new Name("alg2"), new Name("alg3"), new Name("alg4") ];

        List<Name> algorithms = SshClientSettings.DetermineAlgorithms(list, defaultAlgorithms, supportedAlgorithms);

        Assert.Equal(new[] { new Name("alg3") }, algorithms);
    }

    [Fact]
    public void DetermineAlgorithms_Set()
    {
        SshConfig.AlgorithmList list = new()
        {
            Algorithms = new[] { new Name("alg1"), new Name("alg2"), new Name("unsupported")},
            Operation = SshConfig.AlgorithmListOperation.Set,
            PatternList = ""
        };

        List<Name> defaultAlgorithms = [ new Name("alg3"), new Name("alg2") ];
        List<Name> supportedAlgorithms = [ new Name("alg1"), new Name("alg2"), new Name("alg3") ];

        List<Name> algorithms = SshClientSettings.DetermineAlgorithms(list, defaultAlgorithms, supportedAlgorithms);

        Assert.Equal(new[] { new Name("alg1"), new Name("alg2")}, algorithms);
    }

    [Fact]
    public async Task SendEnv()
    {
        const string Config =
        $"""
        SendEnv FOO
        SendEnv -FOO BAR
        SendEnv BAZZ*
        """;
        SshConfig config = await DetermineConfigAsync(Config);

        Assert.Equal(new[] { "BAR", "BAZZ*" }, config.SendEnv);
    }

    [Fact]
    public void DetermineEnvironment()
    {
        List<string> sendEnv = [ "FOO", "BAR*" ];
        Dictionary<string, string> environment = new()
        {
            { "FOO", "foo_value" },
            { "BAR1", "bar1_value" },
            { "BAZ", "baz_value" },
        };

        Dictionary<string, string> expected = new()
        {
            { "FOO", "foo_value" },
            { "BAR1", "bar1_value" }
        };

        Assert.Equal(expected, SshClientSettings.CreateEnvironmentVariables(environment, sendEnv));
    }

    private static async Task<SshConfig> DetermineConfigAsync(string config, string? username = null, string host = "", int? port = null, CancellationToken cancellationToken = default)
    {
        using TempFile tempFile = new TempFile(Path.GetTempFileName());
        File.WriteAllText(tempFile.Path, config);
        return await SshConfig.DetermineConfigForHost(username, host, port, new Dictionary<SshConfigOption, SshConfigOptionValue>(), [tempFile.Path], cancellationToken: default);
    }
}
