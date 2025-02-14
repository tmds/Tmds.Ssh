// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public struct RemoteConnection : IDisposable
{
    internal RemoteConnection(SshDataStream stream, RemoteEndPoint? remoteEndPoint)
    {
        Stream = stream;
        RemoteEndPoint = remoteEndPoint;
    }

    public bool HasStream => Stream is not null;

    public SshDataStream MoveStream()
    {
        var stream = Stream;
        Stream = null;
        return stream ?? throw new InvalidOperationException("There is no stream to obtain.");
    }

    public RemoteEndPoint? RemoteEndPoint { get; }
    public SshDataStream? Stream { get; private set; }

    public void Dispose()
        => Stream?.Dispose();
}