// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh;

interface IPacketDecoder : IDisposable
{
    bool TryDecodePacket(Sequence receiveBuffer, uint sequenceNumber, int maxLength, out Packet packet);
}
