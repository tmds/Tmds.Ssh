using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Tmds.Ssh.Managed.Tests;

public class KnownHostTests : IDisposable
{
    private static readonly string GitHubKey = "AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==";
    private static readonly string HashedHostKey = "AAAAC3NzaC1lZDI1NTE5AAAAINLpitgznNAi49RhCzb9BxMwyPe/VuPya7V7tWRnO10P";
    private static readonly string RevokedKey = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBRF7kE8vbr7bS8HLHNmr4e0Bez8co0l5tgLl1+H7LoLfvHTzMpW0M9FtM9+ObTo6j1gxRp73Cp1ycNwvSm4I4k=";
    private static readonly string KnownHostsContent =
@"github.com,140.82.118.3 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
# line with comments
@revoked trudy ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
  # other line with comments
changed ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIDF+Z3UmAIsuAg1L7vpMnxP9LKU8vBAk4Qb9WzsRK8VSTpTQNzDhha4DTyI9HrBPJ/dNSAf7bjTkGU824myPfM= # comments

@revoked * ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBRF7kE8vbr7bS8HLHNmr4e0Bez8co0l5tgLl1+H7LoLfvHTzMpW0M9FtM9+ObTo6j1gxRp73Cp1ycNwvSm4I4k=

[brackethostname]:1234 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==

wild*hos?na.me ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==

|1|N2OS+FENATANi2PcV/Pk/weRLR8=|owwUJqp0/ouG9BsGvOId6wQcKd0= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINLpitgznNAi49RhCzb9BxMwyPe/VuPya7V7tWRnO10P
";

    private string _knownHostsFilename;

    [Fact]
    public void UnknownHost()
    {
        Assert.Equal(KeyVerificationResult.Unknown, KnownHostsFile.CheckHost(_knownHostsFilename, "unknown", ip: null, 22, new SshKey("type", Array.Empty<byte>())));
    }

    [Fact]
    public void KnownHost()
    {
        Assert.Equal(KeyVerificationResult.Trusted, KnownHostsFile.CheckHost(_knownHostsFilename, "github.com", ip: null, 22, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));
    }

    [Fact]
    public void DefaultPort()
    {
        Assert.Equal(KeyVerificationResult.Unknown, KnownHostsFile.CheckHost(_knownHostsFilename, "github.com", ip: null, 1234, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));
    }

    [Fact]
    public void BracketHostname()
    {
        Assert.Equal(KeyVerificationResult.Trusted, KnownHostsFile.CheckHost(_knownHostsFilename, "brackethostname", ip: null, 1234, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));

        Assert.Equal(KeyVerificationResult.Unknown, KnownHostsFile.CheckHost(_knownHostsFilename, "brackethostname", ip: null, 22, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));
    }

    [Fact]
    public void WildcardHostname()
    {
        Assert.Equal(KeyVerificationResult.Trusted, KnownHostsFile.CheckHost(_knownHostsFilename, "wildcardhostna.me", ip: null, 22, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));

        Assert.Equal(KeyVerificationResult.Unknown, KnownHostsFile.CheckHost(_knownHostsFilename, "wildcardhostnaxme", ip: null, 22, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));

        Assert.Equal(KeyVerificationResult.Unknown, KnownHostsFile.CheckHost(_knownHostsFilename, "prewildcardhostna.me", ip: null, 22, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));

        Assert.Equal(KeyVerificationResult.Unknown, KnownHostsFile.CheckHost(_knownHostsFilename, "wildcardhostna.mepost", ip: null, 22, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));
    }

    [Fact]
    public void KnownIp()
    {
        Assert.Equal(KeyVerificationResult.Trusted, KnownHostsFile.CheckHost(_knownHostsFilename, "", ip: "140.82.118.3", 22, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));
    }

    [Fact]
    public void Revoked()
    {
        Assert.Equal(KeyVerificationResult.Revoked, KnownHostsFile.CheckHost(_knownHostsFilename, "trudy", ip: null, 22, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));
    }

    [Fact]
    public void Changed()
    {
        Assert.Equal(KeyVerificationResult.Changed, KnownHostsFile.CheckHost(_knownHostsFilename, "changed", ip: null, 22, new SshKey("ssh-rsa", Convert.FromBase64String(GitHubKey))));
    }

    [Fact]
    public void WildcardRevoke()
    {
        Assert.Equal(KeyVerificationResult.Revoked, KnownHostsFile.CheckHost(_knownHostsFilename, "changed", ip: null, 22, new SshKey("ecdsa-sha2-nistp256", Convert.FromBase64String(RevokedKey))));
    }

    [Fact]
    public void Hashed()
    {
        Assert.Equal(KeyVerificationResult.Trusted, KnownHostsFile.CheckHost(_knownHostsFilename, "127.0.0.7", ip: null, 22, new SshKey("ssh-ed25519", Convert.FromBase64String(HashedHostKey))));
    }

    public KnownHostTests()
    {
        _knownHostsFilename = Path.GetTempFileName();
        File.WriteAllText(_knownHostsFilename, KnownHostsContent);
    }

    public void Dispose()
    {
        try
        {
            if (_knownHostsFilename != null && File.Exists(_knownHostsFilename))
            {
                File.Delete(_knownHostsFilename);
            }
        }
        catch
        { }
    }
}
