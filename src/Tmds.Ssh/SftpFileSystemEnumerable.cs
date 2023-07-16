// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh;

// TODO: make non-allocating
ref struct SftpFileEntry
{
    private readonly string _path;
    private readonly FileAttributes _attributes;

    internal SftpFileEntry(string path, FileAttributes attributes)
    {
        _path = path;
        _attributes = attributes;
    }

    public ReadOnlySpan<char> Path => _path;

    public FileAttributes GetAttributes() => _attributes;
}

delegate T SftpFileEntryTransform<T>(ref SftpFileEntry entry);

sealed class SftpFileSystemEnumerable<T> : IAsyncEnumerable<T>
{
    private readonly SftpClient _client;
    private readonly string _path;
    private readonly SftpFileEntryTransform<T> _transform;
    private readonly EnumerationOptions _options;

    public SftpFileSystemEnumerable(SftpClient client, string path, SftpFileEntryTransform<T> transform, EnumerationOptions options)
    {
        _client = client;
        _path = path;
        _transform = transform;
        _options = options;
    }

    public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
        => new SftpFileSystemEnumerator<T>(_client, _path, _transform, _options, cancellationToken);
}

sealed class SftpFileSystemEnumerator<T> : IAsyncEnumerator<T>
{
    const int DirectoryEof = -1;
    const int Complete = -2;
    const int Disposed = -3;

    private readonly SftpClient _client;
    private readonly SftpFileEntryTransform<T> _transform;
    private readonly CancellationToken _cancellationToken;

    private string _path;
    private readonly bool _recurseSubdirectories;

    private Queue<string>? _pending;

    private byte[]? _directoryHandle;

    private string? _currentPath;
    private FileAttributes? _currentAttributes;
    private byte[]? _readDirPacket;
    private int _bufferOffset;
    private int _entriesRemaining;
    private ValueTask<byte[]> _readAhead;

    public SftpFileSystemEnumerator(SftpClient client, string path, SftpFileEntryTransform<T> transform, EnumerationOptions options, CancellationToken cancellationToken)
    {
        _client = client;
        _path = path.TrimEnd('/');
        _transform = transform;
        _cancellationToken = cancellationToken;
        _recurseSubdirectories = options.RecurseSubdirectories;
    }

    public T Current
    {
        get
        {
            var entry = CurrentEntry;
            return _transform(ref entry);
        }
    }

    private SftpFileEntry CurrentEntry => new SftpFileEntry(_currentPath!, _currentAttributes!);

    public ValueTask DisposeAsync()
    {
        if (_entriesRemaining != Disposed)
        {
            _entriesRemaining = Disposed;

            if (_directoryHandle is not null)
            {
                _client.CloseFile(_directoryHandle);
            }
        }

        return ValueTask.CompletedTask;
    }

    public async ValueTask<bool> MoveNextAsync()
    {
        if (_entriesRemaining == Disposed)
        {
            throw new ObjectDisposedException(GetType().FullName);
        }

        if (_entriesRemaining == Complete)
        {
            return false;
        }

        do
        {
            while (_entriesRemaining > 0)
            {
                if (ReadNextEntry())
                {
                    return true;
                }
            }
        } while (await TryReadNewBufferAsync());

        _entriesRemaining = Complete;
        return false;
    }

    private async ValueTask<bool> TryReadNewBufferAsync()
    {
        if (_entriesRemaining == DirectoryEof)
        {
            _client.CloseFile(_directoryHandle!);
            _directoryHandle = null;

            if (_pending?.TryDequeue(out string? path) == true)
            {
                
                _path = path;
            }
            else
            {
                return false;
            }
        }

        await ReadNewBufferAsync();
        return true;
    }

    private async ValueTask ReadNewBufferAsync()
    {
        if (_directoryHandle is null)
        {
            _directoryHandle = await _client.OpenDirectoryAsync(_path, _cancellationToken);
            _readAhead = _client.ReadDirAsync(_directoryHandle, _cancellationToken);
        }

        const int CountIndex = 4 /* packet length */ + 1 /* packet type */ + 4 /* id */;

        _readDirPacket = await _readAhead;

        if (_readDirPacket.Length < CountIndex + 4)
        {
            _entriesRemaining = DirectoryEof;
        }
        else
        {
            _readAhead = _client.ReadDirAsync(_directoryHandle, _cancellationToken);
            _entriesRemaining = BinaryPrimitives.ReadInt32BigEndian(_readDirPacket.AsSpan(CountIndex));
            _bufferOffset = CountIndex + 4;
        }
    }

    private bool ReadNextEntry()
    {
        SftpClient.PacketReader reader = new(_readDirPacket.AsSpan(_bufferOffset));
        string name = reader.ReadString();
        _ = reader.ReadString(); // TODO: skip string
        // Each SSH_FXP_READDIR request returns one or more file names with FULL file attributes for each file.
        FileAttributes attributes = reader.ReadFileAttributes();

        // Update offset for the next read.
        _bufferOffset = _readDirPacket!.Length - reader.Remainder.Length;
        _entriesRemaining--;

        // Don't return special directories.
        if (name == "." || name == "..")
        {
            return false;
        }

        _currentPath = $"{_path}/{name}";
        _currentAttributes = attributes;

        if (_recurseSubdirectories && attributes.FileType == PosixFileMode.Directory)
        {
            _pending ??= new();
            _pending.Enqueue(_currentPath);
        }

        return true;
    }
}