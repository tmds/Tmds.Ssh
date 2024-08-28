// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

interface IPacketEncoder : IDisposable
{
    public void Encode(uint sequenceNumber, Packet packet, Sequence buffer);

    protected static byte DeterminePaddingLength(uint length, uint multipleOf)
    {
        uint mask = multipleOf - 1;

        // note: OpenSSH requires padlength to be higher than 4: https://github.com/openssh/openssh-portable/blob/084682786d9275552ee93857cb36e43c446ce92c/packet.c#L1613-L1615
        //       performing an | with multipleOf takes care of that.
        return (byte)((multipleOf - (length & mask)) | multipleOf);
    }
}
