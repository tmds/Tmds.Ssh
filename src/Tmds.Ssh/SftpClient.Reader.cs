// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers.Binary;

namespace Tmds.Ssh
{
    public partial class SftpClient
    {
        ref struct PacketReader
        {
            private ReadOnlySpan<byte> _remainder;

            public ReadOnlySpan<byte> Remainder => _remainder;

            public PacketReader(ReadOnlySpan<byte> packet)
            {
                _remainder = packet;
            }

            public uint ReadUInt()
            {
                uint value = BinaryPrimitives.ReadUInt32BigEndian(_remainder);
                _remainder = _remainder.Slice(4);
                return value;
            }

            public int ReadInt()
            {
                int value = BinaryPrimitives.ReadInt32BigEndian(_remainder);
                _remainder = _remainder.Slice(4);
                return value;
            }

            public string ReadString()
            {
                int length = ReadInt();
                string value = s_utf8Encoding.GetString(_remainder.Slice(0, length));
                _remainder = _remainder.Slice(length);
                return value;
            }

            public byte ReadByte()
            {
                byte value = _remainder[0];
                _remainder = _remainder.Slice(1);
                return value;
            }

            public PacketType ReadPacketType()
            {
                return (PacketType)ReadByte();
            }
        }
    }
}