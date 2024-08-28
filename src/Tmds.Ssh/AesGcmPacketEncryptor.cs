// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class AesGcmPacketEncryptor : IPacketEncryptor
{
    private const int AesBlockSize = 16;

    private readonly AesGcm _aesGcm;
    private readonly byte[] _iv;
    private readonly int _tagLength;

    public AesGcmPacketEncryptor(byte[] key, byte[] iv, int tagLength)
    {
        _iv = iv;
        _tagLength = tagLength;
        _aesGcm = new AesGcm(key, tagLength);
    }

    public void Dispose()
    {
        _aesGcm.Dispose();
    }

    public void Encrypt(uint sequenceNumber, Packet packet, Sequence output)
    {
        using var pkt = packet.Move(); // Dispose the packet.

        // PT MUST be a multiple of 16 octets (the block size of AES)
        uint payload_length = (uint)pkt.PayloadLength;
        //  PT (Plain Text)
        //     byte      padding_length; // 4 <= padding_length < 256
        //     byte[n1]  payload;        // n1 = packet_length-padding_length-1
        //     byte[n2]  random_padding; // n2 = padding_length
        byte padding_length = IPacketEncryptor.DeterminePaddingLength(payload_length + 1, multipleOf: AesBlockSize);
        pkt.WriteHeaderAndPadding(padding_length);

        var unencrypted_packet = pkt.AsReadOnlySequence();
        ReadOnlySpan<byte> associatedData = unencrypted_packet.FirstSpan.Slice(0, 4); // packet_length
        ReadOnlySequence<byte> pt = unencrypted_packet.Slice(4); // PT (Plain Text)
        int textLength = (int)pt.Length;
        int tagLength = _tagLength;
        int encodedLength = 4 + textLength + tagLength;
        ReadOnlySpan<byte> nonce = _iv;

        Span<byte> dst = output.AllocGetSpan(encodedLength);
        associatedData.CopyTo(dst);
        Span<byte> ciphertext = dst.Slice(4, textLength);
        Span<byte> tag = dst.Slice(4 + textLength, tagLength);

        ReadOnlySpan<byte> plaintext;
        if (pt.IsSingleSegment)
        {
            plaintext = pt.FirstSpan;
        }
        else
        {
            // Use the ciphertext span for passing the plaintext to the encrypt operation.
            pt.CopyTo(ciphertext);
            plaintext = ciphertext;
        }

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
