// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Tmds.Ssh
{
    public partial class SftpClient
    {
        internal ref struct PacketReader
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

            public long ReadInt64()
            {
                long value = BinaryPrimitives.ReadInt64BigEndian(_remainder);
                _remainder = _remainder.Slice(8);
                return value;
            }

            public string ReadString()
            {
                int length = ReadInt();
                string value = s_utf8Encoding.GetString(_remainder.Slice(0, length));
                _remainder = _remainder.Slice(length);
                return value;
            }

            public byte[] ReadStringAsBytes()
            {
                int length = ReadInt();
                byte[] value = new byte[length];
                _remainder.Slice(0, length).CopyTo(value);
                _remainder = _remainder.Slice(length);
                return value;
            }

            public byte ReadByte()
            {
                byte value = _remainder[0];
                _remainder = _remainder.Slice(1);
                return value;
            }

            public FileAttributes ReadFileAttributes()
                => ReadFileAttributes(new FileAttributes());

            public FileAttributes ReadFileAttributes(FileAttributes attributes)
            {
                long? length = default;
                int? uid = default;
                int? gid = default;
                PosixFileMode? fileMode = default;
                DateTimeOffset? lastAccessTime = default;
                DateTimeOffset? lastWriteTime = default;
                Dictionary<string, string>? extendedAttributes = default;

                uint flags = ReadUInt();
                if ((flags & 1) != 0)
                {
                    length = ReadInt64();
                }
                if ((flags & 2) != 0)
                {
                    uid = ReadInt();
                    gid = ReadInt();
                }
                if ((flags & 4) != 0)
                {
                    fileMode = (PosixFileMode)ReadInt();
                }
                if ((flags & 8) != 0)
                {
                    lastAccessTime = DateTimeOffset.FromUnixTimeSeconds(ReadUInt());
                    lastWriteTime = DateTimeOffset.FromUnixTimeSeconds(ReadUInt());
                }
                if ((flags & 0x80000000) != 0)
                {
                    uint count = ReadUInt();
                    if (count > 0)
                    {
                        extendedAttributes = new();
                        for (int i = 0; i < count; i++)
                        {
                            extendedAttributes[ReadString()] = ReadString();
                        }
                    }
                }

                attributes.Length = length;
                attributes.Uid = uid;
                attributes.Gid = gid;
                attributes.FileMode = fileMode;
                attributes.LastAccessTime = lastAccessTime;
                attributes.LastWriteTime = lastWriteTime;
                attributes.ExtendedAttributes = extendedAttributes;

                return attributes;
            }

            public PacketType ReadPacketType()
            {
                return (PacketType)ReadByte();
            }
        }
    }
}