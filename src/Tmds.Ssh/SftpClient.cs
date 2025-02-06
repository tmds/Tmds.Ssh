// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

public sealed partial class SftpClient : IDisposable
{
    private readonly Lock _gate = new();

    internal const UnixFilePermissions OwnershipPermissions =
            UnixFilePermissions.UserRead | UnixFilePermissions.UserWrite | UnixFilePermissions.UserExecute |
            UnixFilePermissions.GroupRead | UnixFilePermissions.GroupWrite | UnixFilePermissions.GroupExecute |
            UnixFilePermissions.OtherRead | UnixFilePermissions.OtherWrite | UnixFilePermissions.OtherExecute;

    internal static readonly EnumerationOptions DefaultEnumerationOptions = new();
    internal static readonly UploadEntriesOptions DefaultUploadEntriesOptions = new();
    internal static readonly DownloadEntriesOptions DefaultDownloadEntriesOptions = new();
    internal static readonly FileOpenOptions DefaultFileOpenOptions = new();

    public const UnixFilePermissions DefaultCreateDirectoryPermissions = OwnershipPermissions;

    public const UnixFilePermissions DefaultCreateFilePermissions =
            UnixFilePermissions.UserRead | UnixFilePermissions.UserWrite |
            UnixFilePermissions.GroupRead | UnixFilePermissions.GroupWrite |
            UnixFilePermissions.OtherRead | UnixFilePermissions.OtherWrite;

    private State _state = State.Initial;

    enum State
    {
        Initial,
        Opening,
        Opened,
        Closed,
        Disposed
    }

    private readonly SshClient _client;
    private readonly bool _ownsClient;
    private readonly SftpClientOptions _options;

    private SftpChannel? _channel;
    private SftpDirectory? _workingDirectory;
    private Task<SftpChannel>? _openingTask;

    // For testing.
    internal SshClient SshClient => _client;
    internal bool IsDisposed => _state == State.Disposed;
    internal SftpExtension EnabledExtensions
    {
        get
        {
            SftpChannel channel = _channel ?? throw new InvalidOperationException();
            return channel.EnabledExtensions;
        }
    }

    public SftpClient(string destination, ILoggerFactory? loggerFactory = null, SftpClientOptions? options = null) :
        this(destination, SshConfigSettings.NoConfig, loggerFactory, options)
    { }

    public SftpClient(string destination, SshConfigSettings configSettings, ILoggerFactory? loggerFactory = null, SftpClientOptions? options = null) :
        this(new SshClient(destination, configSettings, loggerFactory), options, ownsClient: true)
    { }

    public SftpClient(SshClientSettings settings, ILoggerFactory? loggerFactory = null, SftpClientOptions? options = null) :
        this(new SshClient(settings, loggerFactory), options, ownsClient: true)
    { }

    public SftpClient(SshClient client, SftpClientOptions? options = null) :
        this(client, options, ownsClient: false)
    {}

    public SftpDirectory GetDirectory(string path)
        => WorkingDirectory.GetDirectory(path);

    private SftpClient(SshClient client, SftpClientOptions? options, bool ownsClient)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
        _options = options ?? SshClient.DefaultSftpClientOptions;
        _ownsClient = ownsClient;
    }

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        State state = _state;
        if (state != State.Initial && state != State.Disposed)
        {
            throw new InvalidOperationException($"{nameof(ConnectAsync)} may only be called once.");
        }
        if (!_ownsClient)
        {
            throw new InvalidOperationException($"{nameof(ConnectAsync)} can not be called when the {nameof(SftpClient)} was created from an {nameof(SshClient)}.");
        }
        await GetChannelAsync(cancellationToken, explicitConnect: true).ConfigureAwait(false);
    }

    internal async ValueTask OpenAsync(CancellationToken cancellationToken)
    {
        await GetChannelAsync(cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<SftpDirectory> GetWorkingDirectoryAsync(CancellationToken cancellationToken)
    {
        if (_workingDirectory is null)
        {
            await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        }
        return _workingDirectory!;
    }

    internal ValueTask<SftpChannel> GetChannelAsync(CancellationToken cancellationToken, bool explicitConnect = false)
    {
        lock (_gate)
        {
            State state = _state;

            if (state == State.Opened)
            {
                return new ValueTask<SftpChannel>(_channel!);
            }

            return OpenCore(state, cancellationToken, explicitConnect);
        }

        ValueTask<SftpChannel> OpenCore(State state, CancellationToken cancellationToken, bool explicitConnect)
        {
            Debug.Assert(_gate.IsHeldByCurrentThread);

            if (state == State.Disposed)
            {
                throw NewObjectDisposedException();
            }

            if (state != State.Opening)
            {
                if (explicitConnect)
                {
                    _openingTask = DoOpenAsync(explicitConnect, cancellationToken);
                    return new ValueTask<SftpChannel>(_openingTask);
                }
                else
                {
                    _openingTask = DoOpenAsync(explicitConnect, default);
                    return new ValueTask<SftpChannel>(_openingTask.WaitAsync(cancellationToken));
                }
            }
            else
            {
                Debug.Assert(_openingTask is not null);

                return WaitForConnectCompletion(_openingTask, cancellationToken);
            }
        }

        static async ValueTask<SftpChannel> WaitForConnectCompletion(Task<SftpChannel> openingTask, CancellationToken cancellationToken)
        {
            await ((Task)openingTask).WaitAsync(cancellationToken).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            cancellationToken.ThrowIfCancellationRequested();
            Debug.Assert(openingTask.IsCompleted);
            if (openingTask.IsCompletedSuccessfully)
            {
                return await openingTask;
            }
            else
            {
                Exception? exception = openingTask.Exception?.InnerException;
                if (exception is null)
                {
                    throw new InvalidOperationException("Cannot determine exception.", openingTask.Exception);
                }
                else if (exception is SshConnectionException connectionException)
                {
                    throw new SshConnectionException("There was a problem with the connection.", connectionException);
                }
                else
                {
                    throw new SshChannelException("Could not open SFTP channel.", exception);
                }
            }
        }
    }

    private async Task<SftpChannel> DoOpenAsync(bool explicitConnect, CancellationToken cancellationToken)
    {
        Debug.Assert(_gate.IsHeldByCurrentThread);

        _channel?.Dispose();
        _channel = null;
        _state = State.Opening;

        bool success = false;
        try
        {
            SftpChannel channel = await _client.OpenSftpChannelAsync(OnChannelAbort, explicitConnect, _workingDirectory?.Path, _options, cancellationToken).ConfigureAwait(false);
            _channel = channel;
            _workingDirectory = new SftpDirectory(this, channel.WorkingDirectory);
            success = true;
            return channel;
        }
        finally
        {
            lock (_gate)
            {
                if (_state == State.Opening)
                {
                    _state = success ? State.Opened : State.Closed;
                }
            }
        }
    }

    private void OnChannelAbort(SshChannel channel)
    {
        lock (_gate)
        {
            if (_state is State.Opening or State.Opened)
            {
                _state = State.Closed;
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_state == State.Disposed)
            {
                return;
            }
            _state = State.Disposed;
        }
        if (_ownsClient)
        {
            _client.Dispose();
        }
        else
        {
            _channel?.Dispose();
        }
    }

    public SftpDirectory WorkingDirectory
    {
        get
        {
            return _workingDirectory ?? throw new InvalidOperationException("The SFTP client has not connected.");
        }
    }

    public ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
        => OpenOrCreateFileAsync(path, access, options: null, cancellationToken);

    public async ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.OpenOrCreateFileAsync(path, access, options, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
        => CreateNewFileAsync(path, access, options: null, cancellationToken);

    public async ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.CreateNewFileAsync(path, access, options, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
        => OpenFileAsync(path, access, options: null, cancellationToken);

    public async ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.OpenFileAsync(path, access, options, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DeleteFileAsync(string path, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.DeleteFileAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DeleteDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.DeleteDirectoryAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.RenameAsync(oldPath, newPath, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask CopyFileAsync(string sourcePath, string destinationPath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.CopyFileAsync(sourcePath, destinationPath, overwrite, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, bool followLinks = true, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.GetAttributesAsync(path, followLinks, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask SetAttributesAsync(
        string path,
        UnixFilePermissions? permissions = default,
        (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
        long? length = default,
        (int Uid, int Gid)? ids = default,
        Dictionary<string, string>? extendedAttributes = default,
        CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.SetAttributesAsync(path, permissions, times, length, ids, extendedAttributes, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<string> GetLinkTargetAsync(string linkPath, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.GetLinkTargetAsync(linkPath, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<string> GetFullPathAsync(string path, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.GetFullPathAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.CreateSymbolicLinkAsync(linkPath, targetPath, cancellationToken).ConfigureAwait(false);
    }

    public IAsyncEnumerable<(string Path, FileEntryAttributes Attributes)> GetDirectoryEntriesAsync(string path, EnumerationOptions? options = null)
        => GetDirectoryEntriesAsync<(string, FileEntryAttributes)>(path, (ref SftpFileEntry entry) => (entry.ToPath(), entry.ToAttributes()), options);

    public IAsyncEnumerable<T> GetDirectoryEntriesAsync<T>(string path, SftpFileEntryTransform<T> transform, EnumerationOptions? options = null)
        => new SftpFileSystemEnumerable<T>(this, path, transform, options ?? DefaultEnumerationOptions);

    public ValueTask CreateDirectoryAsync(string path, CancellationToken cancellationToken)
        => CreateDirectoryAsync(path, createParents: false, DefaultCreateDirectoryPermissions, cancellationToken);

    public async ValueTask CreateDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.CreateDirectoryAsync(path, createParents, permissions, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask CreateNewDirectoryAsync(string path, CancellationToken cancellationToken)
        => CreateNewDirectoryAsync(path, createParents: false, DefaultCreateDirectoryPermissions, cancellationToken);

    public async ValueTask CreateNewDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.CreateNewDirectoryAsync(path, createParents, permissions, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, CancellationToken cancellationToken = default)
        => UploadDirectoryEntriesAsync(localDirPath, remoteDirPath, options: null, cancellationToken);

    public async ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, UploadEntriesOptions? options, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.UploadDirectoryEntriesAsync(localDirPath, remoteDirPath, options, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, CancellationToken cancellationToken)
        => UploadFileAsync(localFilePath, remoteFilePath, overwrite: false, createPermissions: null, cancellationToken);

    public async ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite = false, UnixFilePermissions? createPermissions = default, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.UploadFileAsync(localFilePath, remoteFilePath, overwrite, createPermissions, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask UploadFileAsync(Stream source, string remoteFilePath, CancellationToken cancellationToken)
        => UploadFileAsync(source, remoteFilePath, overwrite: false, createPermissions: DefaultCreateFilePermissions, cancellationToken);

    public async ValueTask UploadFileAsync(Stream source, string remoteFilePath, bool overwrite = false, UnixFilePermissions createPermissions = DefaultCreateFilePermissions, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.UploadFileAsync(source, remoteFilePath, overwrite, createPermissions, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, CancellationToken cancellationToken = default)
        => DownloadDirectoryEntriesAsync(remoteDirPath, localDirPath, options: null, cancellationToken);

    public async ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, DownloadEntriesOptions? options, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.DownloadDirectoryEntriesAsync(remoteDirPath, localDirPath, options, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, CancellationToken cancellationToken)
        => DownloadFileAsync(remoteFilePath, localFilePath, overwrite: false, cancellationToken);

    public async ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.DownloadFileAsync(remoteFilePath, localFilePath, overwrite, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DownloadFileAsync(string remoteFilePath, Stream destination, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.DownloadFileAsync(remoteFilePath, destination, cancellationToken).ConfigureAwait(false);
    }

    private ObjectDisposedException NewObjectDisposedException()
    {
        return new ObjectDisposedException(typeof(SftpClient).FullName);
    }
}
