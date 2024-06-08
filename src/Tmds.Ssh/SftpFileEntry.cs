// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Tmds.Ssh;

public delegate T SftpFileEntryTransform<T>(ref SftpFileEntry entry);
public delegate bool SftpFileEntryPredicate(ref SftpFileEntry entry);

public ref struct SftpFileEntry
{
    private const FileAttributeFlags ExpectedAttributes =
        FileAttributeFlags.SSH_FILEXFER_ATTR_SIZE |
        FileAttributeFlags.SSH_FILEXFER_ATTR_UIDGID |
        FileAttributeFlags.SSH_FILEXFER_ATTR_PERMISSIONS |
        FileAttributeFlags.SSH_FILEXFER_ATTR_ACMODTIME;

    private readonly string _directoryPath;
    private readonly char[] _pathBuffer;
    private readonly char[] _nameBuffer;

    private int _pathLength = 0;
    private int _nameLength = 0;
    private FileEntryAttributes? _attributes;
    private string? _path;

    internal ReadOnlySpan<byte> NameBytes { get; set; }
    public long Length { get; }
    public int Uid { get; }
    public int Gid { get; }
    public UnixFileType FileType { get; }
    public UnixFilePermissions Permissions { get; }
    public DateTimeOffset LastAccessTime { get; }
    public DateTimeOffset LastWriteTime { get; }
    public ReadOnlySpan<char> Path
    {
        get
        {
            if (_pathLength == 0)
            {
                _directoryPath.AsSpan().CopyTo(_pathBuffer);
                int length = _directoryPath.Length;

                _pathBuffer[length] = RemotePath.DirectorySeparatorChar;
                length++;

                ReadOnlySpan<char> filename = FileName;
                filename.CopyTo(_pathBuffer.AsSpan(length));
                length += filename.Length;

                _pathLength = length;
            }

            return _pathBuffer.AsSpan(0, _pathLength);
        }
    }
    public ReadOnlySpan<char> FileName
    {
        get
        {
            if (_nameLength == 0)
            {
                _nameLength = Encoding.UTF8.GetChars(NameBytes, _nameBuffer);
            }

            return _nameBuffer.AsSpan(0, _nameLength);
        }
    }
    public FileEntryAttributes ToAttributes()
        => _attributes ??=
            new FileEntryAttributes()
            {
                Length = this.Length,
                Uid = this.Uid,
                Gid = this.Gid,
                Permissions = this.Permissions,
                FileType = this.FileType,
                LastAccessTime = this.LastAccessTime,
                LastWriteTime = this.LastWriteTime,
                ExtendedAttributes = GetExtendedAttributes()
            };

    private Dictionary<string, string>? GetExtendedAttributes()
    {
        // TODO
        return null;
    }

    public string ToPath()
        => _path ??= new string(Path);

    internal SftpFileEntry(string directoryPath, ReadOnlySpan<byte> entry, char[] pathBuffer, char[] nameBuffer, out int entryLength, FileEntryAttributes? linkTargetAttributes = null)
    {
        _attributes = linkTargetAttributes;
        _path = default;
        _directoryPath = directoryPath;
        _nameBuffer = nameBuffer;
        _pathBuffer = pathBuffer;

        SftpChannel.PacketReader reader = new(entry);
        int nameLength;
        reader.SkipString(out nameLength);
        NameBytes = entry.Slice(4, nameLength);
        if (!RemotePath.IsValidFileName(NameBytes))
        {
            throw new InvalidDataException($"Filename '{Encoding.UTF8.GetString(NameBytes)}' is not a valid SFTP filename.");
        }

        if (linkTargetAttributes is null)
        {
            // Long name.
            reader.SkipString();

            FileAttributeFlags attrFlags = (FileAttributeFlags)reader.ReadUInt();

            // Should have full attributes.
            if ((attrFlags & ExpectedAttributes) != ExpectedAttributes)
            {
                throw new InvalidOperationException();
            }

            Length = reader.ReadInt64();
            Uid = reader.ReadInt();
            Gid = reader.ReadInt();
            (Permissions, FileType) = reader.ReadFileMode();
            LastAccessTime = DateTimeOffset.FromUnixTimeSeconds(reader.ReadUInt());
            LastWriteTime = DateTimeOffset.FromUnixTimeSeconds(reader.ReadUInt());

            if ((attrFlags & FileAttributeFlags.SSH_FILEXFER_ATTR_EXTENDED) != 0)
            {
                uint count = reader.ReadUInt();
                for (int i = 0; i < count; i++)
                {
                    reader.SkipString();
                    reader.SkipString();
                }
            }

            entryLength = entry.Length - reader.Remainder.Length;
        }
        else
        {
            Length = linkTargetAttributes.Length;
            Uid = linkTargetAttributes.Uid;
            Gid = linkTargetAttributes.Gid;
            Permissions = linkTargetAttributes.Permissions;
            FileType = linkTargetAttributes.FileType;
            LastAccessTime = linkTargetAttributes.LastAccessTime;
            LastWriteTime = linkTargetAttributes.LastWriteTime;

            entryLength = -1;
        }
    }
}