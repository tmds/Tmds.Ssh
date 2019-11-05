// This file is part of Tmds.Ssh which is released under MIT.
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
        public int LocalWindowSize { get; protected set; } = 2 * 1024 * 1024;
        public int LocalMaxPacketSize { get { return Constants.MaxDataPacketSize; } }
        public int RemoteMaxPacketSize { get; protected set; }
        public abstract CancellationToken ChannelStopped { get; }
        public abstract ValueTask<Packet> ReceivePacketAsync();
        public abstract ValueTask SendPacketAsync(Packet packet);
        public abstract ValueTask SendChannelDataAsync(ReadOnlyMemory<byte> memory);
        public abstract Packet RentPacket();
        public abstract ValueTask DisposeAsync();
        public abstract void Abort(); // TODO: add exception argument to track abort reason.
        public abstract ValueTask CloseAsync();
        public abstract ValueTask AdjustChannelWindowAsync(int bytesToAdd);
        public abstract void ThrowIfChannelStopped(); // Throws ConnectionClosedException/ChannelAbortedException.
    }
}