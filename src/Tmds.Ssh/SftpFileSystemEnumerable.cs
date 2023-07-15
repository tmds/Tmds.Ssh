using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh;

// TODO: make non-allocating
ref struct SftpFileEntry
{
    private readonly string _name;
    private readonly FileAttributes _attributes;

    internal SftpFileEntry(string name, FileAttributes attributes)
    {
        _name = name;
        _attributes = attributes;
    }

    public ReadOnlySpan<char> FileName => _name;

    public FileAttributes GetAttributes() => _attributes;
}

delegate T SftpFileEntryTransform<T>(ref SftpFileEntry entry);

sealed class SftpFileSystemEnumerable<T> : IAsyncEnumerable<T>
{
    private readonly SftpClient _client;
    private readonly string _path;
    private readonly SftpFileEntryTransform<T> _transform;

    public SftpFileSystemEnumerable(SftpClient client, string path, SftpFileEntryTransform<T> transform)
    {
        _client = client;
        _path = path;
        _transform = transform;
    }

    public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
        => new SftpFileSystemEnumerator<T>(_client, _path, _transform, cancellationToken);
}

sealed class SftpFileSystemEnumerator<T> : IAsyncEnumerator<T>
{
    private readonly SftpClient _client;
    private readonly string _path;
    private readonly SftpFileEntryTransform<T> _transform;
    private readonly CancellationToken _cancellationToken;

    private bool _disposed;
    private string? _directoryHandle;

    private string? _currentName;
    private FileAttributes? _currentAttributes;
    private byte[]? _readDirPacket;
    private int _bufferOffset;
    private int _entriesRemaining;

    public SftpFileSystemEnumerator(SftpClient client, string path, SftpFileEntryTransform<T> transform, CancellationToken cancellationToken)
    {
        _client = client;
        _path = path;
        _transform = transform;
        _cancellationToken = cancellationToken;
    }

    public T Current
    {
        get
        {
            var entry = CurrentEntry;
            return _transform(ref entry);
        }
    }

    private SftpFileEntry CurrentEntry => new SftpFileEntry(_currentName!, _currentAttributes!);

    public ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;

            if (_directoryHandle is not null)
            {
                _client.CloseFile(_directoryHandle);
            }
        }

        return ValueTask.CompletedTask;
    }

    public async ValueTask<bool> MoveNextAsync()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().FullName);
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

            if (_entriesRemaining == -1)
            {
                return false;
            }

            await ReadNewBufferAsync();
        } while (true);
    }

    private async ValueTask ReadNewBufferAsync()
    {
        if (_directoryHandle is null)
        {
            _directoryHandle = await _client.OpenDirectoryAsync(_path, _cancellationToken);
        }

        const int CountIndex = 4 /* packet length */ + 1 /* packet type */ + 4 /* id */;
        // TODO: return current _readDirPacket?
        _readDirPacket = await _client.ReadDirAsync(_directoryHandle, _cancellationToken);
        if (_readDirPacket.Length < CountIndex + 4)
        {
            _entriesRemaining = -1;
        }
        else
        {
            _entriesRemaining = BinaryPrimitives.ReadInt32BigEndian(_readDirPacket.AsSpan(CountIndex));
            _bufferOffset = CountIndex + 4;
        }
    }

    private bool ReadNextEntry()
    {
        SftpClient.PacketReader reader = new(_readDirPacket.AsSpan(_bufferOffset));
        _currentName = reader.ReadString();
        _ = reader.ReadString(); // TODO: skip string
        _currentAttributes = reader.ReadFileAttributes();

        _bufferOffset = _readDirPacket!.Length - reader.Remainder.Length;
        _entriesRemaining--;

        var entry = CurrentEntry;
        return IncludeEntry(ref entry);
    }

    private bool IncludeEntry(ref SftpFileEntry entry)
    {
        return !entry.FileName.SequenceEqual(".") &&
               !entry.FileName.SequenceEqual("..");
    }
}