using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Tmds.Ssh.Managed
{
    sealed class AesGcmPacketEncoder : IPacketEncoder
    {
        private const int AesBlockSize = 16;

        private readonly AesGcm _aesGcm;
        private readonly byte[] _iv;
        private readonly int _tagLength;

        public AesGcmPacketEncoder(byte[] key, byte[] iv, int tagLength)
        {
            _iv = iv;
            _tagLength = tagLength;
            _aesGcm = new AesGcm(key, tagLength);
        }

        public void Dispose()
        {
            _aesGcm.Dispose();
        }

        public void Encode(uint sequenceNumber, Packet packet, Sequence output)
        {
            using var pkt = packet.Move(); // Dispose the packet.

            // PT MUST be a multiple of 16 octets (the block size of AES)
            uint payload_length = (uint)pkt.PayloadLength;
            //  PT (Plain Text)
            //     byte      padding_length; // 4 <= padding_length < 256
            //     byte[n1]  payload;        // n1 = packet_length-padding_length-1
            //     byte[n2]  random_padding; // n2 = padding_length
            byte padding_length = IPacketEncoder.DeterminePaddingLength(payload_length + 1, multipleOf: AesBlockSize);
            pkt.WriteHeaderAndPadding(padding_length);

            var unencrypted_packet = pkt.AsReadOnlySequence();
            ReadOnlySpan<byte> associatedData = unencrypted_packet.FirstSpan.Slice(0, 4); // packet_length
            ReadOnlySequence<byte> pt = unencrypted_packet.Slice(4); // PT (Plain Text)
            ReadOnlySpan<byte> plaintext = pt.IsSingleSegment ? pt.FirstSpan
                                                              : pt.ToArray(); // TODO: avoid allocation.
            ReadOnlySpan<byte> nonce = _iv;

            int textLength = plaintext.Length;
            int tagLength = _tagLength;
            int encodedLength = 4 + textLength + tagLength;
            // append packet_length
            Span<byte> dst = output.AllocGetSpan(encodedLength);
            associatedData.CopyTo(dst);
            // append ciphertext and tag
            Span<byte> ciphertext = dst.Slice(4, textLength);
            Span<byte> tag = dst.Slice(4 + textLength, tagLength);
            _aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            output.AppendAlloced(encodedLength);

            IncrementIV();
        }

        private void IncrementIV()
        {
            // With AES-GCM, the 12-octet IV is broken into two fields: a 4-octet
            // fixed field and an 8-octet invocation counter field.  The invocation
            // field is treated as a 64-bit integer and is incremented after each
            // invocation of AES-GCM to process a binary packet.
            Span<byte> invocationCounter = _iv.AsSpan(4, 8);
            ulong count = BinaryPrimitives.ReadUInt64BigEndian(invocationCounter);
            BinaryPrimitives.WriteUInt64BigEndian(invocationCounter, count + 1);
        }
    }
}