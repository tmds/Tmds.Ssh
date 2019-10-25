// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    abstract class ChannelContext : IAsyncDisposable
    {
        public uint LocalChannel { get; protected set; }
        public uint RemoteChannel { get; protected set; }
        public uint LocalWindowSize { get; protected set; } = int.MaxValue; // TODO...
        public uint LocalMaxPacketSize { get; protected set; } = int.MaxValue; // TODO...
        public uint RemoteWindowSize { get; protected set; }
        public uint RemoteMaxPacketSize { get; protected set; }
        public abstract CancellationToken ChannelStopped { get; }
        public abstract ValueTask<Packet> ReceivePacketAsync();
        public abstract ValueTask SendPacketAsync(Packet packet);
        public abstract Packet RentPacket();
        public abstract ValueTask DisposeAsync();
    }
}