// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers.Binary;

namespace Tmds.Ssh;

sealed class TransformAndHMacPacketEncryptor : IPacketEncryptor
{
    private readonly IDisposableCryptoTransform _transform;
    private readonly IHMac _mac;

    public TransformAndHMacPacketEncryptor(IDisposableCryptoTransform transform, IHMac mac)
    {
        _transform = transform;
        _mac = mac;
    }

    public void Encrypt(uint sequenceNumber, Packet packet, Sequence buffer)
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
        uint multipleOf = (uint)Math.Max(_transform.BlockSize, 8);
        // The minimum size of a packet is 16 (or the cipher block size,
        // whichever is larger)
        uint minSize = (uint)Math.Max(16U, _transform.BlockSize);

        uint payload_length = (uint)pkt.PayloadLength;
        byte padding_length = IPacketEncryptor.DeterminePaddingLength(payload_length + 4 + 1, multipleOf);
        uint packet_length = payload_length + 1 + padding_length;
        while (packet_length < minSize)
        {
            padding_length = (byte)(padding_length + multipleOf);
            packet_length += multipleOf;
        }

        // Write header and padding.
        pkt.WriteHeaderAndPadding(padding_length);

        var unencrypted_packet = pkt.AsReadOnlySequence();

        // Encrypt
        _transform.Transform(unencrypted_packet, buffer);

        // Mac
        // mac = MAC(key, sequence_number || unencrypted_packet)
        Span<byte> sequence_number = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(sequence_number, sequenceNumber);
        _mac.AppendData(sequence_number);
        _mac.AppendData(unencrypted_packet);
        _mac.AppendHashToSequenceAndReset(buffer);
    }

    public void Dispose()
    {
        _transform.Dispose();
        _mac.Dispose();
    }
}
