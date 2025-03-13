// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers.Binary;
using System.Diagnostics;

namespace Tmds.Ssh;

sealed class SftpFileSystemEnumerable<T> : IAsyncEnumerable<T>
{
    private readonly SftpClient? _client;
    private readonly string _path;
    private readonly SftpFileEntryTransform<T> _transform;
    private readonly EnumerationOptions _options;
    private readonly SftpChannel? _channel;

    public SftpFileSystemEnumerable(SftpClient client, string path, SftpFileEntryTransform<T> transform, EnumerationOptions options) :
        this(client, channel: null, path, transform, options)
    { }

    internal SftpFileSystemEnumerable(SftpChannel channel, string path, SftpFileEntryTransform<T> transform, EnumerationOptions options) :
        this(client: null, channel, path, transform, options)
    { }

    private SftpFileSystemEnumerable(SftpClient? client, SftpChannel? channel, string path, SftpFileEntryTransform<T> transform, EnumerationOptions options)
    {
        _client = client;
        _channel = channel;
        _path = path;
        _transform = transform;
        _options = options;
    }

    public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
        => new SftpFileSystemEnumerator<T>(_client, _channel, _path, _transform, _options, cancellationToken);
}

sealed class EnumeratorContext
{
    public readonly char[] PathBuffer = new char[RemotePath.MaxPathLength]; // TODO: pool alloc
    public readonly char[] NameBuffer = new char[RemotePath.MaxNameLength]; // TODO: pool alloc
    public readonly string[]? ExtendedAttributesFilter;

    public EnumeratorContext(string[]? extendedAttributesFilter)
    {
        ExtendedAttributesFilter = extendedAttributesFilter;
    }
}

sealed class SftpFileSystemEnumerator<T> : IAsyncEnumerator<T>
{
    const int DirectoryEof = -1;
    const int Complete = -2;
    const int Disposed = -3;

    private readonly SftpClient? _client;
    private readonly SftpFileEntryTransform<T> _transform;
    private readonly CancellationToken _cancellationToken;

    private readonly bool _recurseSubdirectories;
    private readonly bool _followFileLinks;
    private readonly bool _followDirectoryLinks;
    private readonly UnixFileTypeFilter _fileTypeFilter;
    private readonly SftpFileEntryPredicate? _shouldRecurse;
    private readonly SftpFileEntryPredicate? _shouldInclude;
    private readonly EnumeratorContext _context;

    private Queue<string>? _pending;
    private string? _path;
    private SftpChannel? _channel;
    private SftpFile? _fileHandle;

    private byte[]? _readDirPacket;
    private int _bufferOffset;
    private int _entriesRemaining;
    private ValueTask<byte[]> _readAhead;
    private T? _current;

    public SftpFileSystemEnumerator(SftpClient client, string path, SftpFileEntryTransform<T> transform, EnumerationOptions options, CancellationToken cancellationToken) :
        this(client, channel: null, path, transform, options, cancellationToken)
    { }

    internal SftpFileSystemEnumerator(SftpChannel channel, string path, SftpFileEntryTransform<T> transform, EnumerationOptions options, CancellationToken cancellationToken) :
        this(client: null, channel, path, transform, options, cancellationToken)
    { }

    internal SftpFileSystemEnumerator(SftpClient? client, SftpChannel? channel, string path, SftpFileEntryTransform<T> transform, EnumerationOptions options, CancellationToken cancellationToken)
    {
        Debug.Assert(client != null ^ channel != null);
        _client = client;
        _channel = channel;
        _path = RemotePath.TrimEndingDirectorySeparators(path);
        _transform = transform;
        _cancellationToken = cancellationToken;
        _recurseSubdirectories = options.RecurseSubdirectories;
        _followDirectoryLinks = options.FollowDirectoryLinks;
        _followFileLinks = options.FollowFileLinks;
        _fileTypeFilter = options.FileTypeFilter;
        _shouldInclude = options.ShouldInclude;
        _shouldRecurse = options.ShouldRecurse;
        _context = new (options.ExtendedAttributes);
    }

    public T Current => _current!;

    public ValueTask DisposeAsync()
    {
        if (_entriesRemaining != Disposed)
        {
            _entriesRemaining = Disposed;

            if (_fileHandle is not null)
            {
                _fileHandle.Dispose();
            }
        }

        return ValueTask.CompletedTask;
    }

    public async ValueTask<bool> MoveNextAsync()
    {
        ObjectDisposedException.ThrowIf(_entriesRemaining == Disposed, this);

        if (_entriesRemaining == Complete)
        {
            return false;
        }

        do
        {
            while (_entriesRemaining > 0)
            {
                if (ReadNextEntry(followLink: _followDirectoryLinks || _followFileLinks, out string? linkPath, out Memory<byte> linkEntry))
                {
                    return true;
                }
                if (linkPath is not null &&
                    await ReadLinkTargetEntry(linkPath, linkEntry).ConfigureAwait(false))
                {
                    return true;
                }
            }
        } while (await TryReadNewBufferAsync().ConfigureAwait(false));

        _entriesRemaining = Complete;
        return false;
    }

    private async ValueTask<bool> TryReadNewBufferAsync()
    {
        if (_entriesRemaining == DirectoryEof)
        {
            _fileHandle!.Dispose();
            _fileHandle = null;
            _path = null;
        }

        if (_fileHandle is null)
        {
            await OpenFileHandleAsync();
            if (_fileHandle is null)
            {
                return false;
            }
        }

        await ReadNewBufferAsync().ConfigureAwait(false);
        return true;
    }

    private async ValueTask ReadNewBufferAsync()
    {
        Debug.Assert(_fileHandle is not null);
        Debug.Assert(_channel is not null);

        const int CountIndex = 4 /* packet length */ + 1 /* packet type */ + 4 /* id */;

        _readDirPacket = await _readAhead.ConfigureAwait(false);

        if (_readDirPacket.Length < CountIndex + 4)
        {
            _entriesRemaining = DirectoryEof;
        }
        else
        {
            _readAhead = _channel.ReadDirAsync(_fileHandle, _cancellationToken);
            _entriesRemaining = BinaryPrimitives.ReadInt32BigEndian(_readDirPacket.AsSpan(CountIndex));
            _bufferOffset = CountIndex + 4;
        }
    }

    private async ValueTask OpenFileHandleAsync()
    {
        if (_channel is null)
        {
            Debug.Assert(_client is not null);
            _channel = await _client.GetChannelAsync(_cancellationToken);
            Debug.Assert(_path is not null);
            _path = RemotePath.ResolvePath([_channel.WorkingDirectory, _path]);
        }

        string? path = _path;
        bool isRootPath = path is not null; // path passed to the constructor.
        do
        {
            if (!isRootPath)
            {
                if (_pending?.TryDequeue(out path) != true)
                {
                    return;
                }
            }
            Debug.Assert(path is not null);

            _fileHandle = await _channel.OpenDirectoryAsync(workingDirectory: "", path, _cancellationToken).ConfigureAwait(false);
            if (_fileHandle is null)
            {
                if (isRootPath)
                {
                    throw new SftpException(SftpError.NoSuchFile);
                }
                else
                {
                    continue;
                }
            }
            _path = path;
            _readAhead = _channel.ReadDirAsync(_fileHandle, _cancellationToken);
            return;
        } while (true);
    }

    private bool ReadNextEntry(bool followLink, out string? linkPath, out Memory<byte> linkEntry)
    {
        Debug.Assert(_path is not null);
        int startOffset = _bufferOffset;
        SftpFileEntry entry = new SftpFileEntry(_path, _readDirPacket.AsSpan(startOffset), _context, out int entryLength);

        _bufferOffset += entryLength;
        _entriesRemaining--;

        if (followLink && entry.FileType == UnixFileType.SymbolicLink)
        {
            linkPath = entry.ToPath();
            linkEntry = _readDirPacket.AsMemory(startOffset, entryLength);
            return false;
        }
        linkPath = default;
        linkEntry = default;

        // Don't return "." and "..".
        ReadOnlySpan<byte> entryName = entry.NameBytes;
        if (entryName[0] == '.' && (entryName.Length == 1 || (entryName[1] == '.' && entryName.Length == 2)))
        {
            return false;
        }

        return SetCurrent(ref entry);
    }

    private bool SetCurrent(ref SftpFileEntry entry)
    {
        if (_recurseSubdirectories &&
            entry.FileType == UnixFileType.Directory &&
            (_shouldRecurse?.Invoke(ref entry) ?? true))
        {
            _pending ??= new();
            _pending.Enqueue(entry.ToPath());
        }

        if (!_fileTypeFilter.Matches(entry.FileType))
        {
            return false;
        }

        if (!(_shouldInclude?.Invoke(ref entry) ?? true))
        {
            return false;
        }
        _current = _transform(ref entry);
        return true;
    }

    private async Task<bool> ReadLinkTargetEntry(string linkPath, Memory<byte> linkEntry)
    {
        Debug.Assert(_path is not null);
        FileEntryAttributes? attributes = await _channel!.GetAttributesAsync(workingDirectory: "", linkPath, followLinks: true, _context.ExtendedAttributesFilter, _cancellationToken).ConfigureAwait(false);
        if (attributes is not null)
        {
            if ((!_followDirectoryLinks && attributes.FileType == UnixFileType.Directory) ||
                (!_followFileLinks && attributes.FileType != UnixFileType.Directory))
            {
                attributes = null;
            }
        }
        return SetCurrentEntry();

        bool SetCurrentEntry()
        {
            SftpFileEntry entry = new SftpFileEntry(_path, linkEntry.Span, _context, out int _, attributes);
            return SetCurrent(ref entry);
        }
    }
}
