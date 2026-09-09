// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Delegate for handling SSH agent channels opened by the server.
/// </summary>
/// <param name="channel">The stream for the agent channel. It is disposed when the handler returns.</param>
/// <param name="connectionInfo">The SSH connection information.</param>
/// <param name="cancellationToken">Token canceled when the SSH connection is closed.</param>
/// <remarks>
/// <para>The server opens these channels when <see cref="SshClientSettings.ForwardAgent"/> is enabled.
/// The handler must speak the SSH agent protocol on the stream: it reads requests made by the server and writes back responses.</para>
/// <para>The handler is invoked for each channel. Multiple channels may be handled concurrently.</para>
/// <para>Exceptions thrown by the handler are logged and close the channel.</para>
/// </remarks>
public delegate Task AgentChannelHandler(SshDataStream channel, SshConnectionInfo connectionInfo, CancellationToken cancellationToken);
