// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

internal struct RemoteConnection
{
    public RemoteConnection(SshDataStream stream, RemoteEndPoint? remoteEndPoint)
    {
        Stream = stream;
        RemoteEndPoint = remoteEndPoint;
    }

    public RemoteEndPoint? RemoteEndPoint { get; init; }
    public SshDataStream Stream { get; }
}