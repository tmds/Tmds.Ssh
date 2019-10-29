// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Diagnostics;

namespace Tmds.Ssh
{
    sealed class PacketDecoder : IDisposable
    {
        private readonly IDisposableCryptoTransform _decode;
        private readonly IHMac _mac;
        private readonly SequencePool _sequencePool;
        private Sequence? _decodedPacket;

        public PacketDecoder(SequencePool sequencePool, IDisposableCryptoTransform decode, IHMac mac)
        {
            _decode = decode;
            _mac = mac;
            _sequencePool = sequencePool;
        }

        public PacketDecoder(SequencePool sequencePool) :
            this(sequencePool, EncryptionCryptoTransform.None, HMac.None)
        { }

        public bool TryDecodePacket(Sequence receiveBuffer, int maxLength, out Packet packet)
        {
            // Binary Packet Protocol: https://tools.ietf.org/html/rfc4253#section-6.
            /*
                uint32    packet_length
                byte      padding_length
                byte[n1]  payload; n1 = packet_length - padding_length - 1
                byte[n2]  random padding; n2 = padding_length
                byte[m]   mac (Message Authentication Code - MAC); m = mac_length
            */

            if (_decodedPacket == null)
            {
                _decodedPacket = _sequencePool.RentSequence();
            }

            // We can't decode past the packet, because the mac is not encrypted.
            // We need to know the packet length to know how much we can decrypt.
            while (_decodedPacket.Length < 4 && receiveBuffer.Length >= _decode.BlockSize)
            {
                _decode.Transform(receiveBuffer.AsReadOnlySequence().Slice(0, _decode.BlockSize), _decodedPacket);
                receiveBuffer.Remove(_decode.BlockSize);
            }

            var decodedReader = new SequenceReader(_decodedPacket);
            if (decodedReader.Length >= 4)
            {
                // Read the packet length.
                uint packet_length = decodedReader.ReadUInt32();
                if (packet_length > maxLength)
                {
                    ThrowHelper.ThrowProtocolPacketTooLong();
                }

                // Decode the entire packet.
                uint concatenated_length = 4 + packet_length;
                // verify contatenated_length is a multiple of the cipher block size or 8, whichever is larger.
                uint multipleOf = (uint)Math.Max(_decode.BlockSize, 8);
                if ((concatenated_length % multipleOf) != 0)
                {
                    ThrowHelper.ThrowProtocolInvalidPacketLength();
                }
                long remaining = concatenated_length - decodedReader.Length;
                if (remaining > 0 && receiveBuffer.Length >= remaining)
                {
                    _decode.Transform(receiveBuffer.AsReadOnlySequence().Slice(0, remaining), _decodedPacket);
                    receiveBuffer.Remove(remaining);
                    remaining = 0;
                }

                if (remaining == 0 && receiveBuffer.Length >= _mac.HashSize)
                {
                    if (_decodedPacket.Length != concatenated_length)
                    {
                        ThrowHelper.ThrowInvalidOperation("Complete packet expected.");
                    }

                    // TODO: verify mac
                    receiveBuffer.Remove(_mac.HashSize);

                    packet = new Packet(_decodedPacket);
                    _decodedPacket = null;
                    return true;
                }
            }

            packet = new Packet(null);
            return false;
        }

        public void Dispose()
        {
            _decode?.Dispose();
            _mac.Dispose();
            _decodedPacket?.Dispose();
        }
    }
}