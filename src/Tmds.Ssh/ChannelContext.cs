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
        public abstract CancellationToken ChannelStopped { get; }   // When ChannelCancelled or peer closes channel.
        public abstract CancellationToken ChannelCancelled { get; } // When ConnectionClosed or user calls Cancel.
        public abstract ValueTask<Packet> ReceivePacketAsync(); // TODO: Add a CancellationToken??
        public abstract ValueTask SendPacketAsync(Packet packet);
        public abstract ValueTask SendChannelDataAsync(ReadOnlyMemory<byte> memory);
        public abstract Packet RentPacket();
        public abstract void Cancel(); // TODO: Should this be named Abort and cause ChannelAbortedException??
        public abstract ValueTask CloseAsync();
        public abstract ValueTask AdjustChannelWindowAsync(int bytesToAdd);
        public abstract void ThrowIfChannelStopped();   // Throws ConnectionClosedException, OperationCanceledException, ChannelClosedException.
        public abstract void ThrowIfChannelCancelled(); // Throws ConnectionClosedException, OperationCanceledException.

        public abstract void Dispose();
    }
}