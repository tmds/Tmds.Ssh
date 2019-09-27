// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Diagnostics;

namespace Tmds.Ssh
{
    sealed class PacketDecoder : IDisposable
    {
        public bool TryDecodePacket(Sequence receiveBuffer, SequencePool sequencePool, int maxLength, out Sequence? packet)
        {
            // Binary Packet Protocol: https://tools.ietf.org/html/rfc4253#section-6.
            /*
                uint32    packet_length
                byte      padding_length
                byte[n1]  payload; n1 = packet_length - padding_length - 1
                byte[n2]  random padding; n2 = padding_length
                byte[m]   mac (Message Authentication Code - MAC); m = mac_length
            */
            var reader = new SequenceReader(receiveBuffer);
            if (reader.Length >= 4)
            {
                uint packet_length = reader.ReadUInt32();
                if (packet_length > maxLength)
                {
                    ThrowHelper.ThrowProtocolPacketTooLong();
                }

                if (reader.Remaining >= packet_length)
                {
                    byte padding_length = reader.ReadByte();
                    uint n1 = packet_length - padding_length - 1;

                    // payload
                    bool read = reader.TryRead(n1, out ReadOnlySequence<byte> value);
                    Debug.Assert(read);
                    using var writer = new SequenceWriter(sequencePool);
                    writer.Write(value);

                    // padding
                    reader.Skip(padding_length);

                    // initially there is no mac.

                    // Remove from receiveBuffer.
                    receiveBuffer.Remove(reader.Consumed);

                    packet = writer.BuildSequence();
                    return true;
                }
            }

            packet = null;
            return false;
        }

        public void Dispose()
        { }
    }
}