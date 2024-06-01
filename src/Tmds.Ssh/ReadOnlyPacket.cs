// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

// See Packet.
struct ReadOnlyPacket
{
    private readonly Packet _packet;

    public ReadOnlyPacket(Packet packet)
    {
        _packet = packet;
    }

    public bool IsEmpty
        => _packet.IsEmpty;

    public ReadOnlySequence<byte> Payload
        => _packet.Payload;

    public long PayloadLength
        => _packet.PayloadLength;

    public MessageId? MessageId
        => _packet.MessageId;

    public SequenceReader GetReader()
        => _packet.GetReader();

    public static implicit operator ReadOnlyPacket(Packet p)
        => new ReadOnlyPacket(p);

    public Packet Clone()
        => _packet.Clone();
}
