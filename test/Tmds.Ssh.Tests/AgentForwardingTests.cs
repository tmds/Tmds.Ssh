using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class AgentForwardingTests
{
    private readonly SshServer _sshServer;

    public AgentForwardingTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task NotForwardedByDefault()
    {
        using var client = await _sshServer.CreateClientAsync();

        using var process = await client.ExecuteAsync("echo \"SSH_AUTH_SOCK=[$SSH_AUTH_SOCK]\"");
        (string stdout, _) = await process.ReadToEndAsStringAsync();

        Assert.Contains("SSH_AUTH_SOCK=[]", stdout);
    }

    [Fact]
    public async Task ForwardsToLocalAgent()
    {
        using var agent = new LocalSshAgent();
        agent.Start();
        agent.Add(_sshServer.TestUserIdentityFile);

        using var client = await _sshServer.CreateClientAsync(settings =>
        {
            settings.ForwardAgent = true;
            settings.ForwardAgentAddress = agent.Address;
        });

        // The server sets SSH_AUTH_SOCK when it accepts the forwarding request.
        {
            using var process = await client.ExecuteAsync("echo \"SSH_AUTH_SOCK=[$SSH_AUTH_SOCK]\"");
            (string stdout, _) = await process.ReadToEndAsStringAsync();

            Assert.DoesNotContain("SSH_AUTH_SOCK=[]", stdout);
        }

        // The remote process can list the keys of the local agent.
        {
            using var process = await client.ExecuteAsync("ssh-add -l");
            (string stdout, string stderr) = await process.ReadToEndAsStringAsync();
            int exitCode = await process.GetExitCodeAsync();

            Assert.True(exitCode == 0, $"ssh-add -l failed: {stdout}{stderr}");
            Assert.Contains("SHA256:", stdout);
        }
    }

    [Fact]
    public async Task SessionBindIsAcceptedByAgent()
    {
        // Verifies the 'session-bind@openssh.com' request we send on forwarded agent
        // connections is accepted, which means its signature verifies against the host key.
        using var agent = new LocalSshAgent();
        agent.Start();
        agent.Add(_sshServer.TestUserIdentityFile);

        using var client = await _sshServer.CreateClientAsync();

        using Stream agentStream = await SshAgent.OpenStreamAsync(agent.Address, default);
        bool bound = await SshAgent.TryBindSessionAsync(agentStream, client.ConnectionInfo, isForwarding: true, NullLogger<SshClient>.Instance, default);

        Assert.True(bound);
    }
}
