// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;

namespace Tmds.Ssh
{
    sealed class PacketEncoder : IDisposable
    {
        public void Encode(ReadOnlySequence<byte> payload, Sequence buffer)
        {
            uint cipherBlockSize = 0;
            // the length of the concatenation of 'packet_length',
            // 'padding_length', 'payload', and 'random padding' MUST be a multiple
            // of the cipher block size or 8, whichever is larger.
            uint multipleOf = Math.Max(cipherBlockSize, 8);

            // Binary Packet Protocol: https://tools.ietf.org/html/rfc4253#section-6.
            /*
                uint32    packet_length
                byte      padding_length
                byte[n1]  payload; n1 = packet_length - padding_length - 1
                byte[n2]  random padding; n2 = padding_length
                byte[m]   mac (Message Authentication Code - MAC); m = mac_length
            */
            uint payload_length = (uint)payload.Length;
            byte padding_length = DeterminePaddingLength(payload_length, multipleOf);
            uint packet_length = payload_length + 1 + padding_length;

            // The minimum size of a packet is 16 (or the cipher block size,
            // whichever is larger)
            uint minSize = Math.Max(16U, cipherBlockSize);
            while (packet_length < minSize)
            {
                padding_length = (byte)(padding_length + multipleOf);
                packet_length += multipleOf;
            }

            using var writer = new SequenceWriter(buffer);
            writer.WriteUInt32(packet_length);
            writer.WriteByte(padding_length);
            writer.Write(payload);
            writer.WriteRandomBytes(padding_length);
            // initially, there is no mac.
        }

        private static byte DeterminePaddingLength(uint payload_length, uint multipleOf)
        {
            uint length = payload_length + 4 + 1; // sizeof(packet_length) + sizeof(padding_length)
            uint mask = multipleOf - 1;

            // note: OpenSSH requires padlength to be higher than 4: https://github.com/openssh/openssh-portable/blob/084682786d9275552ee93857cb36e43c446ce92c/packet.c#L1613-L1615
            //       performing an | with multipleOf takes care of that.
            return (byte)((multipleOf - (length & mask)) | multipleOf);
        }

        public void Dispose()
        { }
    }
}