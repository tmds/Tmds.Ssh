// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    abstract class ChannelContext : IDisposable
    {
        public uint LocalChannel { get; protected set; }
        public uint RemoteChannel { get; protected set; }
        public int LocalWindowSize { get; protected set; } = 2 * 1024 * 1024;
        public int LocalMaxPacketSize { get { return Constants.MaxDataPacketSize; } }
        public int RemoteMaxPacketSize { get; protected set; }
        public abstract CancellationToken ChannelStopped { get; } // When ChannelAborted or peer closes channel.
        public abstract CancellationToken ChannelAborted { get; } // When ConnectionClosed or user calls Abort.
        public abstract ValueTask<Packet> ReceivePacketAsync(CancellationToken ct);     // Implicitly uses ChannelAborted.
        public abstract ValueTask SendPacketAsync(Packet packet, CancellationToken ct); // Implicitly uses ChannelStopped.
        public abstract ValueTask SendChannelDataAsync(Packet packet, CancellationToken ct);
        public abstract ValueTask SendChannelDataAsync(ReadOnlyMemory<byte> memory, CancellationToken ct);
        public abstract Packet RentPacket();
        public abstract void Abort(Exception reason);
        public abstract bool IsAborted { get; }
        public abstract ValueTask CloseAsync(CancellationToken ct);
        public abstract void AdjustChannelWindow(int bytesToAdd);
        public abstract void ThrowIfChannelStopped(); // Throws ConnectionClosedException, ChannelAbortedException, ChannelClosedException.
        public abstract void ThrowIfChannelAborted(); // Throws ConnectionClosedException, ChannelAbortedException.

        public abstract void Dispose();
    }
}