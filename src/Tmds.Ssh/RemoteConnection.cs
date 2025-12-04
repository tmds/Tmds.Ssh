// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Represents a connection made to a remote listener.
/// </summary>
public struct RemoteConnection : IDisposable
{
    internal RemoteConnection(SshDataStream stream, RemoteEndPoint? remoteEndPoint)
    {
        Stream = stream;
        RemoteEndPoint = remoteEndPoint;
    }

    /// <summary>
    /// Gets whether a <see cref="Stream"/> is available.
    /// </summary>
    public bool HasStream => Stream is not null;

    /// <summary>
    /// Transfers ownership of the <see cref="Stream"/> to the caller for handling the connection.
    /// </summary>
    /// <returns>The <see cref="Stream"/>.</returns>
    public SshDataStream MoveStream()
    {
        var stream = Stream;
        Stream = null;
        return stream ?? throw new InvalidOperationException("There is no stream to obtain.");
    }

    /// <summary>
    /// Gets the remote endpoint of the connection.
    /// </summary>
    /// <remarks>
    /// <para>For <see cref="SshClient.ListenTcpAsync"/>, the type is <see cref="RemoteIPEndPoint"/>.</para>
    /// <para>For <see cref="SshClient.ListenUnixAsync"/>, the value is <see langword="null"/>.</para>
    /// </remarks>
    public RemoteEndPoint? RemoteEndPoint { get; }

    /// <summary>
    /// Gets the data <see cref="Stream"/> (<see langword="null"/> after MoveStream is called).
    /// </summary>
    public SshDataStream? Stream { get; private set; }

    /// <summary>
    /// Disposes the <see cref="Stream"/> when not moved.
    /// </summary>
    public void Dispose()
        => Stream?.Dispose();
}