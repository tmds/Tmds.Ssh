// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

// https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
sealed class ChaCha20Poly1305PacketEncoder : ChaCha20Poly1305PacketEncDecBase, IPacketEncoder
{
    public ChaCha20Poly1305PacketEncoder(byte[] key) :
        base(key)
    { }

    public void Dispose()
    { }

    public void Encode(uint sequenceNumber, Packet packet, Sequence output)
    {
        using var pkt = packet.Move(); // Dispose the packet.

        ConfigureCiphers(sequenceNumber);

        // Padding.
        uint payload_length = (uint)pkt.PayloadLength;
        //  PT (Plain Text)
        //     byte      padding_length; // 4 <= padding_length < 256
        //     byte[n1]  payload;        // n1 = packet_length-padding_length-1
        //     byte[n2]  random_padding; // n2 = padding_length
        byte padding_length = IPacketEncoder.DeterminePaddingLength(payload_length + 1, multipleOf: PaddTo);
        pkt.WriteHeaderAndPadding(padding_length);

        var unencrypted_packet = pkt.AsReadOnlySequence();
        ReadOnlySpan<byte> packet_length = unencrypted_packet.FirstSpan.Slice(0, LengthSize); // packet_length
        ReadOnlySequence<byte> pt = unencrypted_packet.Slice(LengthSize); // PT (Plain Text)

        int textLength = (int)pt.Length;
        int encodedLength = LengthSize + textLength + TagSize;
        Span<byte> dst = output.AllocGetSpan(encodedLength);

        // Encrypt length.
        Span<byte> length_encrypted = dst.Slice(0, LengthSize);
        LengthCipher.ProcessBytes(packet_length, length_encrypted);

        // Encrypt payload.
        Span<byte> ciphertext = dst.Slice(LengthSize, textLength);
        if (pt.IsSingleSegment)
        {
            PayloadCipher.ProcessBytes(pt.FirstSpan, ciphertext);
        }
        else
        {
            foreach (var memory in pt)
            {
                PayloadCipher.ProcessBytes(memory.Span, ciphertext);
                ciphertext = ciphertext.Slice(memory.Length);
            }
        }

        // Mac.
        Span<byte> tag = dst.Slice(LengthSize + textLength, TagSize);
        Mac.BlockUpdate(dst.Slice(0, LengthSize + textLength));
        Mac.DoFinal(tag);

        output.AppendAlloced(encodedLength);
    }
}
