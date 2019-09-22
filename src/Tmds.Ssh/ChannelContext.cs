// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    abstract class ChannelContext
    {
        public int ChannelNumber { get; protected set; }
        public abstract CancellationToken ChannelStopped { get; }
        public abstract ValueTask<Sequence> ReadPacketAsync();
        public abstract ValueTask SendPacketAsync(Sequence packet);
        public abstract Sequence RentSequence();
    }
}