// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

/// <summary>
/// Provides a client for performing filesystem operations on SSH servers using SFTP (SSH File Transfer Protocol).
/// </summary>
/// <remarks>
/// <para>
/// When the application already has an SSH connection for an <see cref="SshClient"/>, that connection can also be used for the <see cref="SftpClient"/>:
/// <list type="bullet">
/// <item>Call <see cref="SshClient.OpenSftpClientAsync(CancellationToken)"/> to create an <see cref="SftpClient"/> from an existing <see cref="SshClient"/>.</item>
/// <item>Or, use the constructor that accepts an existing <see cref="SshClient"/>.</item>
/// </list>
/// </para>
/// <para>
/// For SFTP-only scenarios, the <see cref="SftpClient"/> can be created so it owns and manages the SSH connection:
/// <list type="bullet">
/// <item>Use the constructor that accepts a destination string that uses SSH credentials for the current user for authentication and OpenSSH <c>known_hosts</c> for host key validation.</item>
/// <item>Use the constructor that accepts <see cref="SshClientSettings"/> to change the default settings.</item>
/// <item>Use the constructor that accepts <see cref="SshConfigSettings"/> to use configuration from OpenSSH config files.</item>
/// </list>
/// </para>
/// <para>
/// By default, the SFTP connection is established automatically when the first operation is performed.
/// When the <see cref="SftpClient"/> owns the SSH connection, you can explicitly call <see cref="ConnectAsync(CancellationToken)"/> to establish the connection before performing operations.
/// </para>
/// <para>
/// Once the connection is established, the <see cref="SftpClient"/> methods can be used to perform various filesystem operations.
/// </para>
/// </remarks>
/// <example>
/// The following example uploads and downloads files.
/// It uses default credentials for the current user and authenticates the server against the <c>known_hosts</c> files:
/// <code>
/// using Tmds.Ssh;
///
/// using var sftpClient = new SftpClient("user@example.com");
/// await sftpClient.UploadFileAsync("/local/path/file.txt", "/remote/path/file.txt");
/// await sftpClient.DownloadFileAsync("/remote/path/file.txt", "/local/path/downloaded.txt");
/// </code>
/// </example>
public sealed partial class SftpClient : ISftpDirectory, IDisposable
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

    /// <summary>
    /// Default permissions for creating directories (rwxrwxrwx).
    /// </summary>
    /// <remarks>
    /// The server will apply a umask which filters these permissions further.
    /// </remarks>
    public const UnixFilePermissions DefaultCreateDirectoryPermissions = OwnershipPermissions;

    /// <summary>
    /// Default permissions for creating files (rw-rw-rw-).
    /// </summary>
    /// <remarks>
    /// The server will apply a umask which filters these permissions further.
    /// </remarks>
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

    /// <summary>
    /// Creates an <see cref="SftpClient"/> for the specified destination.
    /// </summary>
    /// <param name="destination">The destination in format [user@]host[:port].</param>
    /// <param name="loggerFactory">Optional logger factory.</param>
    /// <param name="options"><see cref="SftpClientOptions"/> for the <see cref="SftpClient"/>.</param>
    public SftpClient(string destination, ILoggerFactory? loggerFactory = null, SftpClientOptions? options = null) :
        this(destination, SshConfigSettings.NoConfig, loggerFactory, options)
    { }

    /// <summary>
    /// Creates an <see cref="SftpClient"/> for the specified destination with SSH config settings.
    /// </summary>
    /// <param name="destination">The destination in format [user@]host[:port].</param>
    /// <param name="configSettings">SSH configuration settings.</param>
    /// <param name="loggerFactory">Optional logger factory.</param>
    /// <param name="options"><see cref="SftpClientOptions"/> for the <see cref="SftpClient"/>.</param>
    public SftpClient(string destination, SshConfigSettings configSettings, ILoggerFactory? loggerFactory = null, SftpClientOptions? options = null) :
        this(new SshClient(destination, configSettings, loggerFactory), options, ownsClient: true)
    { }

    /// <summary>
    /// Creates an <see cref="SftpClient"/> with the specified settings.
    /// </summary>
    /// <param name="settings">The <see cref="SshClientSettings"/>.</param>
    /// <param name="loggerFactory">Optional logger factory.</param>
    /// <param name="options"><see cref="SftpClientOptions"/> for the <see cref="SftpClient"/>.</param>
    public SftpClient(SshClientSettings settings, ILoggerFactory? loggerFactory = null, SftpClientOptions? options = null) :
        this(new SshClient(settings, loggerFactory), options, ownsClient: true)
    { }

    /// <summary>
    /// Creates an <see cref="SftpClient"/> from an existing <see cref="SshClient"/>.
    /// </summary>
    /// <param name="client">The <see cref="SshClient"/> to use for connections.</param>
    /// <param name="options"><see cref="SftpClientOptions"/> for the <see cref="SftpClient"/>.</param>
    public SftpClient(SshClient client, SftpClientOptions? options = null) :
        this(client, options, ownsClient: false)
    {}

    /// <inheritdoc />
    public SftpDirectory GetDirectory(string path)
        => WorkingDirectory.GetDirectory(path);

    ISftpDirectory ISftpDirectory.GetDirectory(string path)
        => GetDirectory(path);

    string ISftpDirectory.Path
        => WorkingDirectory.Path;

    private SftpClient(SshClient client, SftpClientOptions? options, bool ownsClient)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
        _options = options ?? SshClient.DefaultSftpClientOptions;
        _ownsClient = ownsClient;
    }

    /// <summary>
    /// Connect to the server.
    /// </summary>
    /// <remarks>
    /// This method can only be used when the <see cref="SftpClient"/> was constructed using a constructor that accepts a destination or <see cref="SshClientSettings"/>.
    /// </remarks>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
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

    /// <summary>
    /// Closes the connection and releases resources.
    /// </summary>
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

    /// <summary>
    /// Gets the working directory for the SftpClient.
    /// </summary>
    /// <remarks>
    /// This property can only be used once the client is connected.
    /// </remarks>
    public SftpDirectory WorkingDirectory
    {
        get
        {
            return _workingDirectory ?? throw new InvalidOperationException("The SFTP client has not connected.");
        }
    }

    /// <inheritdoc />
    public async ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.OpenOrCreateFileAsync(path, access, options, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.CreateNewFileAsync(path, access, options, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.OpenFileAsync(path, access, options, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask DeleteFileAsync(string path, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.DeleteFileAsync(path, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask DeleteDirectoryAsync(string path, bool recursive = false, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.DeleteDirectoryAsync(path, recursive, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.RenameAsync(oldPath, newPath, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask CopyFileAsync(string sourcePath, string destinationPath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.CopyFileAsync(sourcePath, destinationPath, overwrite, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, bool followLinks, string[]? filter, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.GetAttributesAsync(path, followLinks, filter, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask SetAttributesAsync(
        string path,
        UnixFilePermissions? permissions = default,
        (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
        long? length = default,
        (int Uid, int Gid)? ids = default,
        IEnumerable<KeyValuePair<string, Memory<byte>>>? extendedAttributes = default,
        CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.SetAttributesAsync(path, permissions, times, length, ids, extendedAttributes, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<string> GetLinkTargetAsync(string linkPath, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.GetLinkTargetAsync(linkPath, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<string> GetRealPathAsync(string path, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        return await dir.GetRealPathAsync(path, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.CreateSymbolicLinkAsync(linkPath, targetPath, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public IAsyncEnumerable<T> GetDirectoryEntriesAsync<T>(string path, SftpFileEntryTransform<T> transform, EnumerationOptions? options = null)
        => new SftpFileSystemEnumerable<T>(this, path, transform, options ?? DefaultEnumerationOptions);

    /// <inheritdoc />
    public async ValueTask CreateDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.CreateDirectoryAsync(path, createParents, permissions, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask CreateNewDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.CreateNewDirectoryAsync(path, createParents, permissions, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, UploadEntriesOptions? options, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.UploadDirectoryEntriesAsync(localDirPath, remoteDirPath, options, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite = false, UnixFilePermissions? createPermissions = default, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.UploadFileAsync(localFilePath, remoteFilePath, overwrite, createPermissions, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask UploadFileAsync(Stream source, string remoteFilePath, bool overwrite = false, UnixFilePermissions createPermissions = DefaultCreateFilePermissions, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.UploadFileAsync(source, remoteFilePath, overwrite, createPermissions, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, DownloadEntriesOptions? options, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.DownloadDirectoryEntriesAsync(remoteDirPath, localDirPath, options, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        var dir = await GetWorkingDirectoryAsync(cancellationToken).ConfigureAwait(false);
        await dir.DownloadFileAsync(remoteFilePath, localFilePath, overwrite, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
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
