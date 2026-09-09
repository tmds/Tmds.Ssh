// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// Implements the client side of 'auth-agent-req@openssh.com'/'auth-agent@openssh.com' agent forwarding.
static class AgentForwarding
{
    private const int BufferSize = 4096;

    // Proxies an agent channel opened by the server to the SSH agent at 'address'.
    public static async Task ProxyToLocalAgentAsync(SshDataStream channel, string address, SshConnectionInfo connectionInfo, CancellationToken cancellationToken)
    {
        using Stream agentStream = await SshAgent.OpenStreamAsync(address, cancellationToken).ConfigureAwait(false);

        // Binding tells the agent this connection is forwarded, which enables it to
        // apply the constraints of keys that are restricted to specific destinations.
        await SshAgent.TryBindSessionAsync(agentStream, connectionInfo, isForwarding: true, cancellationToken).ConfigureAwait(false);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        Task serverToAgent = CopyAsync(channel, agentStream, cts.Token);
        Task agentToServer = CopyAsync(agentStream, channel, cts.Token);

        Task completedTask = await Task.WhenAny(serverToAgent, agentToServer).ConfigureAwait(false);

        // Stop copying in the other direction.
        cts.Cancel();
        try
        {
            await Task.WhenAll(serverToAgent, agentToServer).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { }

        // Throw when the copy that completed first failed.
        await completedTask.ConfigureAwait(false);

        static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
        {
            byte[] buffer = new byte[BufferSize];
            while (true)
            {
                int bytesRead = await from.ReadAsync(buffer, ct).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    return;
                }
                await to.WriteAsync(buffer.AsMemory(0, bytesRead), ct).ConfigureAwait(false);
            }
        }
    }
}
