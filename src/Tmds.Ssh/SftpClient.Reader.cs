// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

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

            public void SkipString()
            {
                int length = ReadInt();
                _remainder = _remainder.Slice(length);
            }

            public void SkipString(out int length)
            {
                length = ReadInt();
                _remainder = _remainder.Slice(length);
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

            public FileEntryAttributes ReadFileAttributes()
                => ReadFileAttributes(new FileEntryAttributes());

            public FileEntryAttributes ReadFileAttributes(FileEntryAttributes attributes)
            {
                // In practice, most servers will include all these values.
                // So in case it doesn't, we use sentinel value instead of forcing a user to deal with nullable properties.
                long length = -1;
                int uid = -1;
                int gid = -1;
                UnixFileType fileType = 0;
                UnixFilePermissions permissions = 0;
                DateTimeOffset lastAccessTime = DateTimeOffset.MinValue;
                DateTimeOffset lastWriteTime = DateTimeOffset.MinValue;
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
                    (permissions, fileType) = ReadFileMode();
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
                attributes.Permissions = permissions;
                attributes.FileType = fileType;
                attributes.LastAccessTime = lastAccessTime;
                attributes.LastWriteTime = lastWriteTime;
                attributes.ExtendedAttributes = extendedAttributes;

                return attributes;
            }

            public PacketType ReadPacketType()
            {
                return (PacketType)ReadByte();
            }

            public (UnixFilePermissions, UnixFileType) ReadFileMode()
            {
                int mode = ReadInt();
                UnixFilePermissions permissions = (UnixFilePermissions)(mode & 0xfff);
                UnixFileType fileType = ((UnixFileTypeByte)(mode >> 12)) switch
                {
                    UnixFileTypeByte.RegularFile => UnixFileType.RegularFile,
                    UnixFileTypeByte.Directory => UnixFileType.Directory,
                    UnixFileTypeByte.SymbolicLink => UnixFileType.SymbolicLink,
                    UnixFileTypeByte.CharacterDevice => UnixFileType.CharacterDevice,
                    UnixFileTypeByte.BlockDevice => UnixFileType.BlockDevice,
                    UnixFileTypeByte.Socket => UnixFileType.Socket,
                    UnixFileTypeByte.Fifo => UnixFileType.Fifo,
                    _ => throw new InvalidDataException($"Invalid mode: {mode}.")
                };
                return (permissions, fileType);
            }
        }
    }
}