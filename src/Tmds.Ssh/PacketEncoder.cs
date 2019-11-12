// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Tmds.Ssh
{
    sealed class PacketEncoder : IDisposable
    {
        private readonly IDisposableCryptoTransform _encode;
        private readonly IDisposableCryptoTransform _mac;

        public PacketEncoder(IDisposableCryptoTransform encode, IDisposableCryptoTransform mac)
        {
            _encode = encode;
            _mac = mac;
        }

        public PacketEncoder() :
            this(EncryptionCryptoTransform.None, HMac.None)
        { }

        public void Encode(uint sequenceNumber, Packet packet, Sequence buffer)
        {
            using var pkt = packet.Move(); // Dispose the packet.

            // Binary Packet Protocol: https://tools.ietf.org/html/rfc4253#section-6.
            /*
                uint32    packet_length
                byte      padding_length
                byte[n1]  payload; n1 = packet_length - padding_length - 1
                byte[n2]  random padding; n2 = padding_length
                byte[m]   mac (Message Authentication Code - MAC); m = mac_length
            */

            // the length of the concatenation of 'packet_length',
            // 'padding_length', 'payload', and 'random padding' MUST be a multiple
            // of the cipher block size or 8, whichever is larger.
            uint multipleOf = (uint)Math.Max(_encode.BlockSize, 8);
            // The minimum size of a packet is 16 (or the cipher block size,
            // whichever is larger)
            uint minSize = (uint)Math.Max(16U, _encode.BlockSize);

            uint payload_length = (uint)pkt.PayloadLength;
            byte padding_length = DeterminePaddingLength(payload_length, multipleOf);
            uint packet_length = payload_length + 1 + padding_length;
            while (packet_length < minSize)
            {
                padding_length = (byte)(padding_length + multipleOf);
                packet_length += multipleOf;
            }

            // Write header and padding.
            pkt.WriteHeaderAndPadding(padding_length);

            // Encode
            _encode.Transform(pkt.AsReadOnlySequence(), buffer);

            // Mac
            // mac = MAC(key, sequence_number || unencrypted_packet)
            Span<byte> prefix = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(prefix, sequenceNumber);
            _mac.Transform(prefix, pkt.AsReadOnlySequence(), default, buffer);
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
        {
            _encode.Dispose();
            _mac.Dispose();
        }
    }
}