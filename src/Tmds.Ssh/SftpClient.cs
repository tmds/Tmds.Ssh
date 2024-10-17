// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

public sealed partial class SftpClient : IDisposable
{
    private readonly object _gate = new object();

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
        await GetChannelAsync(cancellationToken);
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
            Debug.Assert(Monitor.IsEntered(_gate));

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
        Debug.Assert(Monitor.IsEntered(_gate));

        _channel?.Dispose();
        _channel = null;
        _state = State.Opening;

        bool success = false;
        try
        {
            SftpChannel channel = await _client.OpenSftpChannelAsync(OnChannelAbort, explicitConnect, _options, cancellationToken).ConfigureAwait(false);
            _channel = channel;
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

    public ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
        => OpenOrCreateFileAsync(path, access, options: null, cancellationToken);

    public async ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
        => await OpenFileAsync(path, SftpOpenFlags.OpenOrCreate, access, options, cancellationToken).ConfigureAwait(false)
            ?? throw new SftpException(SftpError.NoSuchFile);

    public ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
        => CreateNewFileAsync(path, access, options: null, cancellationToken);

    public async ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
        => await OpenFileAsync(path, SftpOpenFlags.CreateNew, access, options, cancellationToken).ConfigureAwait(false)
            ?? throw new SftpException(SftpError.NoSuchFile);

    public ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default)
        => OpenFileAsync(path, access, options: null, cancellationToken);

    public async ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
        => await OpenFileAsync(path, SftpOpenFlags.Open, access, options, cancellationToken).ConfigureAwait(false);

    private async ValueTask<SftpFile?> OpenFileAsync(string path, SftpOpenFlags flags, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        return await channel.OpenFileAsync(path, flags, access, options ?? DefaultFileOpenOptions, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DeleteFileAsync(string path, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.DeleteFileAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DeleteDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.DeleteDirectoryAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.RenameAsync(oldPath, newPath, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask CopyFileAsync(string sourcePath, string destinationPath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.CopyFileAsync(sourcePath, destinationPath, overwrite, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, bool followLinks = true, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        return await channel.GetAttributesAsync(path, followLinks, cancellationToken).ConfigureAwait(false);
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
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.SetAttributesAsync(path, permissions, times, length, ids, extendedAttributes, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<string> GetLinkTargetAsync(string linkPath, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        return await channel.GetLinkTargetAsync(linkPath, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<string> GetFullPathAsync(string path, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        return await channel.GetFullPathAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.CreateSymbolicLinkAsync(linkPath, targetPath, overwrite: false, cancellationToken).ConfigureAwait(false);
    }

    public IAsyncEnumerable<(string Path, FileEntryAttributes Attributes)> GetDirectoryEntriesAsync(string path, EnumerationOptions? options = null)
        => GetDirectoryEntriesAsync<(string, FileEntryAttributes)>(path, (ref SftpFileEntry entry) => (entry.ToPath(), entry.ToAttributes()), options);

    public IAsyncEnumerable<T> GetDirectoryEntriesAsync<T>(string path, SftpFileEntryTransform<T> transform, EnumerationOptions? options = null)
        => new SftpFileSystemEnumerable<T>(this, path, transform, options ?? DefaultEnumerationOptions);

    internal async ValueTask<SftpFile> OpenDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        return await channel.OpenDirectoryAsync(path, cancellationToken);
    }

    public ValueTask CreateDirectoryAsync(string path, CancellationToken cancellationToken)
        => CreateDirectoryAsync(path, createParents: false, DefaultCreateDirectoryPermissions, cancellationToken);

    public async ValueTask CreateDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.CreateDirectoryAsync(path, createParents, permissions, cancellationToken);
    }

    public ValueTask CreateNewDirectoryAsync(string path, CancellationToken cancellationToken)
        => CreateNewDirectoryAsync(path, createParents: false, DefaultCreateDirectoryPermissions, cancellationToken);

    public async ValueTask CreateNewDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.CreateNewDirectoryAsync(path, createParents, permissions, cancellationToken);
    }

    public ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, CancellationToken cancellationToken = default)
        => UploadDirectoryEntriesAsync(localDirPath, remoteDirPath, options: null, cancellationToken);

    public async ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, UploadEntriesOptions? options, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.UploadDirectoryEntriesAsync(localDirPath, remoteDirPath, options, cancellationToken);
    }

    public ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, CancellationToken cancellationToken)
        => UploadFileAsync(localFilePath, remoteFilePath, overwrite: false, createPermissions: null, cancellationToken);

    public async ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite = false, UnixFilePermissions? createPermissions = default, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.UploadFileAsync(localFilePath, remoteFilePath, length: null, overwrite, createPermissions, cancellationToken);
    }

    public ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, CancellationToken cancellationToken = default)
        => DownloadDirectoryEntriesAsync(remoteDirPath, localDirPath, options: null, cancellationToken);

    public async ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, DownloadEntriesOptions? options, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.DownloadDirectoryEntriesAsync(remoteDirPath, localDirPath, options, cancellationToken);
    }

    public ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, CancellationToken cancellationToken)
        => DownloadFileAsync(remoteFilePath, localFilePath, overwrite: false, cancellationToken);

    public async ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken).ConfigureAwait(false);
        await channel.DownloadFileAsync(remoteFilePath, localFilePath, overwrite, cancellationToken);
    }

    private ObjectDisposedException NewObjectDisposedException()
    {
        return new ObjectDisposedException(typeof(SftpClient).FullName);
    }
}
