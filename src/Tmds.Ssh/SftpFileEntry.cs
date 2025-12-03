// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Text;

namespace Tmds.Ssh;

/// <summary>
/// Delegate for transforming an SftpFileEntry to a result.
/// </summary>
/// <typeparam name="T">The transformation result type.</typeparam>
/// <param name="entry">The file entry to transform.</param>
/// <returns>The transformed value.</returns>
public delegate T SftpFileEntryTransform<T>(ref SftpFileEntry entry);

/// <summary>
/// Delegate for filtering file entries.
/// </summary>
/// <param name="entry">The file entry to evaluate.</param>
/// <returns>True to include the entry, false to exclude.</returns>
public delegate bool SftpFileEntryPredicate(ref SftpFileEntry entry);

/// <summary>
/// Represents an filesystem entry during enumeration.
/// </summary>
public ref struct SftpFileEntry
{
    private const FileAttributeFlags ExpectedAttributes =
        FileAttributeFlags.SSH_FILEXFER_ATTR_SIZE |
        FileAttributeFlags.SSH_FILEXFER_ATTR_UIDGID |
        FileAttributeFlags.SSH_FILEXFER_ATTR_PERMISSIONS |
        FileAttributeFlags.SSH_FILEXFER_ATTR_ACMODTIME;

    private readonly string _directoryPath;
    private readonly EnumeratorContext _context;

    private int _pathLength = 0;
    private int _nameLength = 0;
    private FileEntryAttributes? _attributes;
    private string? _path;

    internal ReadOnlySpan<byte> NameBytes { get; set; }
    internal ReadOnlySpan<byte> AttributesBytes { get; set; }

    /// <summary>
    /// Gets the file length in bytes.
    /// </summary>
    public long Length { get; }

    /// <summary>
    /// Gets the user ID.
    /// </summary>
    public int Uid { get; }

    /// <summary>
    /// Gets the group ID.
    /// </summary>
    public int Gid { get; }

    /// <summary>
    /// Gets the file type.
    /// </summary>
    public UnixFileType FileType { get; }

    /// <summary>
    /// Gets the file permissions.
    /// </summary>
    public UnixFilePermissions Permissions { get; }

    /// <summary>
    /// Gets the last access time.
    /// </summary>
    public DateTimeOffset LastAccessTime { get; }

    /// <summary>
    /// Gets the last write time.
    /// </summary>
    public DateTimeOffset LastWriteTime { get; }

    /// <summary>
    /// Gets the full path to the entry.
    /// </summary>
    public ReadOnlySpan<char> Path
    {
        get
        {
            char[] pathBuffer = _context.PathBuffer;
            if (_pathLength == 0)
            {
                int length = _directoryPath.Length;
                if (length > 0)
                {
                    _directoryPath.AsSpan().CopyTo(pathBuffer);

                    // Append '/' unless _directorPath == '/'.
                    if (length != 1 || _directoryPath[0] != RemotePath.DirectorySeparatorChar)
                    {
                        pathBuffer[length] = RemotePath.DirectorySeparatorChar;
                        length++;
                    }
                }

                ReadOnlySpan<char> filename = FileName;
                filename.CopyTo(pathBuffer.AsSpan(length));
                length += filename.Length;

                _pathLength = length;
            }

            return pathBuffer.AsSpan(0, _pathLength);
        }
    }

    /// <summary>
    /// Gets the file name without directory path.
    /// </summary>
    public ReadOnlySpan<char> FileName
    {
        get
        {
            char[] nameBuffer = _context.NameBuffer;
            if (_nameLength == 0)
            {
                _nameLength = Encoding.UTF8.GetChars(NameBytes, nameBuffer);
            }

            return nameBuffer.AsSpan(0, _nameLength);
        }
    }

    /// <summary>
    /// Gets the attributes.
    /// </summary>
    /// <returns>The <see cref="FileEntryAttributes"/>.</returns>
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

    private Dictionary<string, byte[]>? GetExtendedAttributes()
    {
        Dictionary<string, byte[]>? dict = null;

        string[]? filter = _context.ExtendedAttributesFilter;

        if (!AttributesBytes.IsEmpty && (filter?.Length != 0))
        {
            SftpChannel.PacketReader reader = new(AttributesBytes);
            uint count = reader.ReadUInt();
            for (int i = 0; i < count; i++)
            {
                string key = reader.ReadString();
                if (filter?.Contains(key) != false)
                {
                    dict ??= new();
                    dict[key] = reader.ReadStringAsByteArray();
                }
            }
        }

        return dict;
    }

    /// <summary>
    /// Gets the full path of the entry as a string.
    /// </summary>
    /// <returns>The full path.</returns>
    public string ToPath()
        => _path ??= new string(Path);

    internal SftpFileEntry(string directoryPath, ReadOnlySpan<byte> entry, EnumeratorContext context, out int entryLength, FileEntryAttributes? linkTargetAttributes = null)
    {
        _attributes = linkTargetAttributes;
        _path = default;
        _directoryPath = directoryPath;
        _context = context;

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

            AttributesBytes = default;
            if ((attrFlags & FileAttributeFlags.SSH_FILEXFER_ATTR_EXTENDED) != 0)
            {
                AttributesBytes = reader.Remainder;
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