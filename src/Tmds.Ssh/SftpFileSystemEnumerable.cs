// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh;

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
    private readonly char[] _pathBuffer = new char[RemotePath.MaxPathLength]; // TODO: pool alloc
    private readonly char[] _nameBuffer = new char[RemotePath.MaxNameLength]; // TODO: pool alloc

    private string _path;
    private readonly bool _recurseSubdirectories;

    private Queue<string>? _pending;

    private byte[]? _directoryHandle;

    private byte[]? _readDirPacket;
    private int _bufferOffset;
    private int _entriesRemaining;
    private ValueTask<byte[]> _readAhead;
    private T? _current;

    public SftpFileSystemEnumerator(SftpClient client, string path, SftpFileEntryTransform<T> transform, EnumerationOptions options, CancellationToken cancellationToken)
    {
        _client = client;
        _path = RemotePath.TrimEndingDirectorySeparator(path);
        _transform = transform;
        _cancellationToken = cancellationToken;
        _recurseSubdirectories = options.RecurseSubdirectories;
    }

    public T Current => _current!;

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
        SftpFileEntry entry = new SftpFileEntry(_path, _readDirPacket.AsSpan(_bufferOffset), _pathBuffer, _nameBuffer, out int entryLength);

        _bufferOffset += entryLength;
        _entriesRemaining--;

        // Don't return "." and "..".
        ReadOnlySpan<byte> entryName = entry.NameBytes;
        if (entryName[0] == '.' && (entryName.Length == 1 || (entryName[1] == '.' && entryName.Length == 2)))
        {
            return false;
        }

        if (_recurseSubdirectories && entry.FileType == UnixFileType.Directory)
        {
            _pending ??= new();
            _pending.Enqueue(entry.ToPath());
        }

        _current = _transform(ref entry);
        return true;
    }
}
