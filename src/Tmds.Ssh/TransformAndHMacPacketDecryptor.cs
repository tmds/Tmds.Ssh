// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Buffers.Binary;

namespace Tmds.Ssh;

sealed class TransformAndHMacPacketDecryptor : IPacketDecryptor
{
    private readonly IDisposableCryptoTransform _transform;
    private readonly IHMac _mac;
    private readonly byte[] _macBuffer;
    private readonly SequencePool _sequencePool;
    private Sequence? _decodedPacket;

    public TransformAndHMacPacketDecryptor(SequencePool sequencePool, IDisposableCryptoTransform transform, IHMac mac)
    {
        _transform = transform;
        _mac = mac;
        _macBuffer = new byte[_mac.HashSize];
        _sequencePool = sequencePool;
    }

    public bool TryDecrypt(Sequence receiveBuffer, uint sequenceNumber, int maxLength, out Packet packet)
    {
        // Binary Packet Protocol: https://tools.ietf.org/html/rfc4253#section-6.
        /*
            uint32    packet_length
            byte      padding_length
            byte[n1]  payload; n1 = packet_length - padding_length - 1
            byte[n2]  random padding; n2 = padding_length
            byte[m]   mac (Message Authentication Code - MAC); m = mac_length
        */

        if (_mac.IsEncryptThenMac)
        {
            return TryDecryptEncryptThenMac(receiveBuffer, sequenceNumber, maxLength, out packet);
        }

        if (_decodedPacket == null)
        {
            _decodedPacket = _sequencePool.RentSequence();
        }

        // We can't decode past the packet, because the mac is not encrypted.
        // We need to know the packet length to know how much we can decrypt.
        while (_decodedPacket.Length < 4 && receiveBuffer.Length >= _transform.BlockSize)
        {
            _transform.Transform(receiveBuffer.AsReadOnlySequence().Slice(0, _transform.BlockSize), _decodedPacket);
            receiveBuffer.Remove(_transform.BlockSize);
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
            uint multipleOf = (uint)Math.Max(_transform.BlockSize, 8);
            if ((concatenated_length % multipleOf) != 0)
            {
                ThrowHelper.ThrowProtocolInvalidPacketLength();
            }
            long remaining = concatenated_length - decodedReader.Length;
            if (remaining > 0 && receiveBuffer.Length >= remaining)
            {
                _transform.Transform(receiveBuffer.AsReadOnlySequence().Slice(0, remaining), _decodedPacket);
                receiveBuffer.Remove(remaining);
                remaining = 0;
            }

            if (remaining == 0 && receiveBuffer.Length >= _mac.HashSize)
            {
                if (_decodedPacket.Length != concatenated_length)
                {
                    ThrowHelper.ThrowInvalidOperation("Complete packet expected.");
                }

                if (_mac.HashSize > 0)
                {
                    Span<byte> sequence_number = stackalloc byte[4];
                    BinaryPrimitives.WriteUInt32BigEndian(sequence_number, sequenceNumber);
                    _mac.AppendData(sequence_number);
                    _mac.AppendData(_decodedPacket.AsReadOnlySequence());
                    receiveBuffer.CopyTo(_macBuffer, _mac.HashSize);
                    if (!_mac.CheckHashAndReset(_macBuffer))
                    {
                        ThrowHelper.ThrowProtocolIncorrectMac();
                    }

                    receiveBuffer.Remove(_mac.HashSize);
                }

                packet = new Packet(_decodedPacket);
                _decodedPacket = null;
                return true;
            }
        }

        packet = new Packet(null);
        return false;
    }

    // Encrypt-then-MAC: 'packet_length' is not encrypted and the MAC is computed over the encrypted packet.
    // This enables verifying the MAC before decrypting anything.
    private bool TryDecryptEncryptThenMac(Sequence receiveBuffer, uint sequenceNumber, int maxLength, out Packet packet)
    {
        packet = new Packet(null);

        if (receiveBuffer.Length < 4)
        {
            return false;
        }

        Span<byte> packet_length_bytes = stackalloc byte[4];
        receiveBuffer.CopyTo(packet_length_bytes, 4);
        uint packet_length = BinaryPrimitives.ReadUInt32BigEndian(packet_length_bytes);
        if (packet_length > maxLength)
        {
            ThrowHelper.ThrowProtocolPacketTooLong();
        }

        // The encrypted part must be a multiple of the cipher block size or 8, whichever is larger.
        uint multipleOf = (uint)Math.Max(_transform.BlockSize, 8);
        if (packet_length == 0 || (packet_length % multipleOf) != 0)
        {
            ThrowHelper.ThrowProtocolInvalidPacketLength();
        }

        long totalLength = 4 + packet_length + _mac.HashSize;
        if (receiveBuffer.Length < totalLength)
        {
            return false;
        }

        ReadOnlySequence<byte> received = receiveBuffer.AsReadOnlySequence();

        // Verify the mac before decrypting.
        // mac = MAC(key, sequence_number || packet_length || encrypted_packet)
        Span<byte> sequence_number = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(sequence_number, sequenceNumber);
        _mac.AppendData(sequence_number);
        _mac.AppendData(received.Slice(0, 4 + packet_length));
        received.Slice(4 + packet_length, _mac.HashSize).CopyTo(_macBuffer);
        if (!_mac.CheckHashAndReset(_macBuffer))
        {
            ThrowHelper.ThrowProtocolIncorrectMac();
        }

        _decodedPacket ??= _sequencePool.RentSequence();

        // The unencrypted 'packet_length' is part of the decoded packet.
        // Reserve room for the first encrypted block too so it ends up in the same segment.
        packet_length_bytes.CopyTo(_decodedPacket.AllocGetSpan(4 + _transform.BlockSize));
        _decodedPacket.AppendAlloced(4);

        _transform.Transform(received.Slice(4, packet_length), _decodedPacket);
        receiveBuffer.Remove(totalLength);

        packet = new Packet(_decodedPacket);
        _decodedPacket = null;
        return true;
    }

    public void Dispose()
    {
        _transform?.Dispose();
        _mac.Dispose();
        _decodedPacket?.Dispose();
    }
}
