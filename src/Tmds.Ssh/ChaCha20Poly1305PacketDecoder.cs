// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class ChaCha20Poly1305PacketDecoder : ChaCha20Poly1305PacketEncDecBase, IPacketDecoder
{
    private readonly SequencePool _sequencePool;
    private int _currentPacketLength = -1;

    public ChaCha20Poly1305PacketDecoder(SequencePool sequencePool, byte[] key) :
        base(key)
    {
        _sequencePool = sequencePool;
    }

    public void Dispose()
    { }

    public bool TryDecodePacket(Sequence receiveBuffer, uint sequenceNumber, int maxLength, out Packet packet)
    {
        packet = new Packet(null);

        // Wait for the length.
        if (receiveBuffer.Length < LengthSize)
        {
            return false;
        }

        // Decrypt length.
        int packetLength = _currentPacketLength;
        Span<byte> length_unencrypted = stackalloc byte[LengthSize];
        if (packetLength == -1)
        {
            ConfigureCiphers(sequenceNumber);

            Span<byte> length_encrypted = stackalloc byte[LengthSize];
            if (receiveBuffer.FirstSpan.Length >= LengthSize)
            {
                receiveBuffer.FirstSpan.Slice(0, LengthSize).CopyTo(length_encrypted);
            }
            else
            {
                receiveBuffer.AsReadOnlySequence().Slice(0, LengthSize).CopyTo(length_encrypted);
            }

            LengthCipher.ProcessBytes(length_encrypted, length_unencrypted);

            // Verify the packet length isn't too long and properly padded.
            uint packet_length = BinaryPrimitives.ReadUInt32BigEndian(length_unencrypted);
            if (packet_length > maxLength || (packet_length % PaddTo) != 0)
            {
                ThrowHelper.ThrowProtocolPacketTooLong();
            }

            _currentPacketLength = packetLength = (int)packet_length;
        }
        else
        {
            BinaryPrimitives.WriteInt32BigEndian(length_unencrypted, _currentPacketLength);
        }

        // Wait for the full encrypted packet.
        int total_length = LengthSize + packetLength + TagSize;
        if (receiveBuffer.Length < total_length)
        {
            return false;
        }

        // Check the mac.
        ReadOnlySequence<byte> receiveBufferROSequence = receiveBuffer.AsReadOnlySequence();
        ReadOnlySequence<byte> hashed = receiveBufferROSequence.Slice(0, LengthSize + packetLength);
        Span<byte> packetTag = stackalloc byte[TagSize];
        receiveBufferROSequence.Slice(LengthSize + packetLength, TagSize).CopyTo(packetTag);
        if (hashed.IsSingleSegment)
        {
            Mac.BlockUpdate(hashed.FirstSpan);
        }
        else
        {
            foreach (var memory in hashed)
            {
                Mac.BlockUpdate(memory.Span);
            }
        }
        Span<byte> tag = stackalloc byte[TagSize];
        Mac.DoFinal(tag);
        if (!CryptographicOperations.FixedTimeEquals(packetTag, tag))
        {
            throw new CryptographicException();
        }

        int decodedLength = total_length - TagSize;
        Sequence decoded = _sequencePool.RentSequence();
        Span<byte> dst = decoded.AllocGetSpan(decodedLength);

        // Decrypt length.
        length_unencrypted.CopyTo(dst);

        // Decrypt payload.
        Span<byte> plaintext = dst.Slice(LengthSize, packetLength);
        ReadOnlySequence<byte> ciphertext = receiveBufferROSequence.Slice(LengthSize, packetLength);
        if (ciphertext.IsSingleSegment)
        {
            PayloadCipher.ProcessBytes(ciphertext.FirstSpan, plaintext);
        }
        else
        {
            foreach (var memory in ciphertext)
            {
                PayloadCipher.ProcessBytes(memory.Span, plaintext);
                plaintext = plaintext.Slice(memory.Length);
            }
        }

        decoded.AppendAlloced(decodedLength);
        packet = new Packet(decoded);

        receiveBuffer.Remove(total_length);

        _currentPacketLength = -1; // start decoding a new packet

        return true;
    }
}
