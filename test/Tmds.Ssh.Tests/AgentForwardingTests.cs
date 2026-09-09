using System.Buffers.Binary;
using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class AgentForwardingTests
{
    private const byte SSH_AGENTC_REQUEST_IDENTITIES = 11;
    private const byte SSH_AGENT_FAILURE = 5;

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
    public async Task ChannelHandlerHandlesRequests()
    {
        List<byte> requestTypes = new();

        using var client = await _sshServer.CreateClientAsync(settings =>
        {
            settings.ForwardAgent = true;
            settings.AgentChannelHandler = async (channel, connectionInfo, cancellationToken) =>
            {
                // Refuse every request without contacting a local agent.
                while (true)
                {
                    byte[]? request = await ReadAgentMessageAsync(channel, cancellationToken);
                    if (request is null)
                    {
                        return;
                    }
                    lock (requestTypes)
                    {
                        requestTypes.Add(request[0]);
                    }
                    await WriteAgentMessageAsync(channel, [ SSH_AGENT_FAILURE ], cancellationToken);
                }
            };
        });

        using var process = await client.ExecuteAsync("ssh-add -l");
        (string stdout, string stderr) = await process.ReadToEndAsStringAsync();
        int exitCode = await process.GetExitCodeAsync();

        Assert.True(exitCode != 0, $"ssh-add -l was expected to fail: {stdout}{stderr}");
        lock (requestTypes)
        {
            Assert.Contains(SSH_AGENTC_REQUEST_IDENTITIES, requestTypes);
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
        bool bound = await SshAgent.TryBindSessionAsync(agentStream, client.ConnectionInfo, isForwarding: true, default);

        Assert.True(bound);
    }

    private static async Task<byte[]?> ReadAgentMessageAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] lengthBuffer = new byte[4];
        int bytesRead = await stream.ReadAsync(lengthBuffer, cancellationToken);
        if (bytesRead == 0)
        {
            return null;
        }
        if (bytesRead != lengthBuffer.Length)
        {
            await stream.ReadExactlyAsync(lengthBuffer.AsMemory(bytesRead), cancellationToken);
        }
        uint length = BinaryPrimitives.ReadUInt32BigEndian(lengthBuffer);
        Assert.InRange(length, 1u, 64 * 1024u);
        byte[] message = new byte[length];
        await stream.ReadExactlyAsync(message, cancellationToken);
        return message;
    }

    private static async Task WriteAgentMessageAsync(Stream stream, byte[] message, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[4 + message.Length];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)message.Length);
        message.CopyTo(buffer, 4);
        await stream.WriteAsync(buffer, cancellationToken);
    }
}
