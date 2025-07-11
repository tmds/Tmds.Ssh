[![NuGet](https://img.shields.io/nuget/v/Tmds.Ssh.svg)](https://www.nuget.org/packages/Tmds.Ssh)

# Tmds.Ssh

`Tmds.Ssh` is a modern, managed .NET SSH client library for .NET 6+.

## Getting Started

Create a new Console application:
```sh
dotnet new console -o example
cd example
dotnet add package Tmds.Ssh
```

Update `Program.cs`:
```cs
using Tmds.Ssh;

using var sshClient = new SshClient("localhost");
using var process = await sshClient.ExecuteAsync("echo 'hello world!'");
(bool isError, string? line) = await process.ReadLineAsync();
Console.WriteLine(line);
```

Now run the application:
```sh
$ dotnet run
hello world!
```

See [Getting Started](docs/getting-started.md) for more information.

## Examples

The following are some example projects that show how Tmds.Ssh can be used:

- [scp](./examples/scp) - SCP client to copy/fetch files
- [ssh](./examples/ssh) - SSH client
- [azure_key](./examples/azure_key) - SSH client with private keys stored in Azure Key Vault.

## API

```cs
namespace Tmds.Ssh;

class SshClient : IDisposable
{
  // Connect to the destination. No additional config.
  SshClient(string destination, ILoggerFactory? loggerFactory = null);
  // Use OpenSSH config files and options to configure the client.
  SshClient(string destination, SshConfigSettings configSettings, ILoggerFactory? loggerFactory = null);
  // Use the .NET SshClientSettings API to configure the client.
  SshClient(SshClientSettings settings, ILoggerFactory? loggerFactory = null);

  // Calling ConnectAsync is optional when SshClientSettings.AutoConnect is set (default).
  Task ConnectAsync(CancellationToken cancellationToken);

  // Not usable with AutoReconnect.
  // A connection must be established before calling this.
  CancellationToken Disconnected { get; }

  /** Execute remote processes **/
  Task<RemoteProcess> ExecuteAsync(string command, CancellationToken cancellationToken);
  Task<RemoteProcess> ExecuteAsync(string command, ExecuteOptions? options = null, CancellationToken cancellationToken = default);
  Task<RemoteProcess> ExecuteShellAsync(CancellationToken cancellationToken);
  Task<RemoteProcess> ExecuteShellAsync(ExecuteOptions? options = null, CancellationToken cancellationToken = default);
  Task<RemoteProcess> ExecuteSubsystemAsync(string subsystem, CancellationToken cancellationToken);
  Task<RemoteProcess> ExecuteSubsystemAsync(string subsystem, ExecuteOptions? options = null, CancellationToken cancellationToken = default);

  /** Forward connections **/
  Task<SshDataStream> OpenTcpConnectionAsync(string host, int port, CancellationToken cancellationToken = default);
  Task<SshDataStream> OpenUnixConnectionAsync(string path, CancellationToken cancellationToken = default);
  Task<RemoteListener> ListenTcpAsync(string address, int port, CancellationToken cancellationToken = default);
  Task<RemoteListener> ListenUnixAsync(string path, CancellationToken cancellationToken = default);
  // bindEP can be an IPEndPoint or a UnixDomainSocketEndPoint.
  // remoteEP can be a RemoteHostEndPoint, a RemoteUnixEndPoint or a RemoteIPEndPoint.
  Task<LocalForward> StartForwardAsync(EndPoint bindEP, RemoteEndPoint remoteEP, CancellationToken cancellationToken = default);
  Task<SocksForward> StartForwardSocksAsync(EndPoint bindEP, CancellationToken cancellationToken = default);
  // bindEP can be a RemoteIPListenEndPoint or a RemoteUnixEndPoint.
  // localEP can be a DnsEndPoint, an IPEndPoint or a UnixDomainSocketEndPoint.
  Task<RemoteForward> StartRemoteForwardAsync(RemoteEndPoint bindEP, EndPoint localEP, CancellationToken cancellationToken = default);

  /** File system operations **/
  Task<SftpClient> OpenSftpClientAsync(CancellationToken cancellationToken);
  Task<SftpClient> OpenSftpClientAsync(SftpClientOptions? options = null, CancellationToken cancellationToken = default)
}
class ExecuteOptions
{
  Encoding StandardInputEncoding { get; set; }
  Encoding StandardErrorEncoding { get; set; }
  Encoding StandardOutputEncoding { get; set; }

  // Often SSH servers don't accept environment variables (for security).
  // When AllocateTerminal is set, 'TERM' is ignored when it does not match 'TerminalType'.
  Dictionary<string, string> EnvironmentVariables { get; set; } = [];

  bool AllocateTerminal { get; set; } = false;
  string TerminalType { get; set; } = "xterm-256color";
  int TerminalWidth { get; set; } = 80;
  int TerminalHeight { get; set; } = 24;
  TerminalSettings TerminalSettings { get; }
}
class RemoteProcess : IDisposable
{
  // Read from the remote process (bytes).
  ValueTask ReadToEndAsync(Stream? stdoutStream, Stream? stderrStream, CancellationToken? cancellationToken);
  ValueTask<(bool isError, int bytesRead)> ReadAsync(Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken cancellationToken = default);
  ValueTask ReadToEndAsync(Func<Memory<byte>, object, CancellationToken, ValueTask> handleStdout, object? stdoutContext, Func<Memory<byte>, object, CancellationToken, ValueTask> handleStderr, object? stderrContext, CancellationToken? cancellationToken);
  // Read from the remote process (chars/strings). After using these APIs, APIs that read bytes may no longer be used.
  ValueTask<(bool isError, string? line)> ReadLineAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default);
  ValueTask<(string stdout, string stderr)> ReadToEndAsStringAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default);
  IAsyncEnumerable<(bool isError, string line)> ReadAllLinesAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default);
  ValueTask<(bool isError, int bytesRead)> ReadAsync(Memory<char>? stdoutBuffer, Memory<char>? stderrBuffer, CancellationToken cancellationToken = default);

  // Write to the remote process (bytes).
  ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default);
  Stream StandardInputStream { get; } // Disposing/Closing the Stream calls WriteEof.
  // Write to the remote process (chars/strings).
  ValueTask WriteAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default);
  ValueTask WriteAsync(string value, CancellationToken cancellationToken = default);
  ValueTask WriteLineAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default);
  ValueTask WriteLineAsync(string? value, CancellationToken cancellationToken = default);
  StreamWriter StandardInputWriter { get; }
  // Write EOF.
  void WriteEof();

  // Send a signal. Returns 'false' if the remote process had already terminated.
  bool SendSignal(string signalName);

  // Wait for the remote process to exit.
  ValueTask WaitForExitAsync(CancellationToken cancellationToken);

  // CancellationToken that cancels when operations involving the remote process should stop.
  CancellationToken ExecutionAborted { get; }

  // Terminal operations.
  bool HasTerminal { get; }
  bool SetTerminalSize(int width, int height); // Returns 'false' if the remote process had already terminated.

  // Exit code.
  int ExitCode { get; }
  // Exit signal (if terminated by a signal).
  string? ExitSignal { get; }
}
class SshDataStream : Stream
{
  void WriteEof();
  CancellationToken StreamAborted { get; }
}
class TerminalSettings
{
  // ...
}
// Represents a Socket EndPoint on the server side.
class RemoteEndPoint
{ }
class RemoteHostEndPoint(string host, int port) : RemoteEndPoint
{ }
class RemoteIPEndPoint(IPAddress address, int port) : RemoteEndPoint
{ }
class RemoteUnixEndPoint(string path) : RemoteEndPoint
{ }
class RemoteIPListenEndPoint(string address, int port) : RemoteEndPoint
{ }
class LocalForward : IDisposable
{
  EndPoint LocalEndPoint { get; }
  CancellationToken Stopped { get; }
  void ThrowIfStopped();
}
class SocksForward : IDisposable
{
  EndPoint LocalEndPoint { get; }
  CancellationToken Stopped { get; }
  void ThrowIfStopped();
}
class RemoteForward : IDisposable
{
  RemoteEndPoint RemoteEndPoint { get; }
  CancellationToken Stopped { get; }
  void ThrowIfStopped();
}
class RemoteListener : IDisposable
{
  // For ListenTcpAsync, type is RemoteIPListenEndPoint.
  // For ListenUnixAsync, type is UnixDomainSocketEndPoint.
  RemoteEndPoint ListenEndPoint { get; }

  // This method throws when the SshClient disconnects (SshConnectionClosedException), or the RemoteListener is disposed (ObjectDisposedException).
  // Calling Stop makes the method return a default(RemoteConnection) instead.
  ValueTask<RemoteConnection> AcceptAsync(CancellationToken cancellationToken = default);

  void Stop();
}
struct RemoteConnection : IDisposable
{
  // For ListenTcpAsync, type is RemoteIPEndPoint.
  // For ListenUnixAsync, value is 'null'.
  RemoteEndPoint? RemoteEndPoint { get; }

  SshDataStream? Stream { get; }
  bool HasStream { get; }
  Stream MoveStream(); // Transfers ownership of the Stream to the caller.
}
class SftpClient : ISftpDirectory, IDisposable
{
  // Note: umask is applied on the server.
  const UnixFilePermissions DefaultCreateDirectoryPermissions; // = '-rwxrwxrwx'.
  const UnixFilePermissions DefaultCreateFilePermissions;      // = '-rw-rw-rw-'.

  // The SftpClient owns the connection.
  SftpClient(string destination, ILoggerFactory? loggerFactory = null, SftpClientOptions? options = null);
  SftpClient(string destination, SshConfigSettings configSettings, ILoggerFactory? loggerFactory = null, SftpClientOptions? options = null);
  SftpClient(SshClientSettings settings, ILoggerFactory? loggerFactory = null, SftpClientOptions? options = null);

  // The SshClient owns the connection.
  SftpClient(SshClient client, SftpClientOptions? options = null);

  // Only usable when the SftpClient was constructed directly using the constructor that accepts a destination/SshClientSettings.
  Task ConnectAsync(CancellationToken cancellationToken = default);

  // May be used once the client is connected.
  SftpDirectory WorkingDirectory { get; }  // The working directory used for SftpClient operations.
}
class SftpDirectory : ISftpDirectory
{ }
interface ISftpDirectory // Represents a working directory.
{
  string Path { get; }

  ISftpDirectory GetDirectory(string path);

  ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default);
  ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default);
  ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default);
  ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default);
  // Returns null if the file does not exist.
  ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default);
  // Returns null if the file does not exist.
  ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, FileOpenOptions? options, CancellationToken cancellationToken = default);

  // Does not throw if the path did not exist.
  ValueTask DeleteFileAsync(string path, CancellationToken cancellationToken = default);

  // Does not throw if the path is an existing directory, or a link to one.
  ValueTask CreateDirectoryAsync(string path, CancellationToken cancellationToken);
  ValueTask CreateDirectoryAsync(string path, bool createParents = false, UnixFilePermissions createPermissions = DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default);
  // Throws if the path exists.
  ValueTask CreateNewDirectoryAsync(string path, CancellationToken cancellationToken);
  ValueTask CreateNewDirectoryAsync(string path, bool createParents = false, UnixFilePermissions permissions = DefaultCreateDirectoryPermissions, CancellationToken cancellationToken = default);

  // Does not throw if the path did not exist.
  ValueTask DeleteDirectoryAsync(string path, CancellationToken cancellationToken);
  ValueTask DeleteDirectoryAsync(string path, bool recursive = false, CancellationToken cancellationToken = default);

  ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default);

  ValueTask CopyFileAsync(string sourcePath, string destinationPath, bool overwrite = false, CancellationToken cancellationToken = default);

  ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, CancellationToken cancellationToken); // No extended attributes are returned.
  ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, bool followLinks = true, CancellationToken cancellationToken = default); // No extended attributes are returned.
  ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, bool followLinks, string[]? filter, CancellationToken cancellationToken = default); // 'filter' determines what extended attributes are returned.
  ValueTask SetAttributesAsync(
    string path,
    UnixFilePermissions? permissions = default,
    (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
    long? length = default,
    (int Uid, int Gid)? ids = default,
    IEnumerable<KeyValuePair<string, Memory<byte>>>? extendedAttributes = default,
    CancellationToken cancellationToken = default);

  IAsyncEnumerable<(string Path, FileEntryAttributes Attributes)> GetDirectoryEntriesAsync(string path, EnumerationOptions? options = null);
  IAsyncEnumerable<T> GetDirectoryEntriesAsync<T>(string path, SftpFileEntryTransform<T> transform, EnumerationOptions? options = null);

  ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, CancellationToken cancellationToken);
  ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite = false, UnixFilePermissions? createPermissions = null, CancellationToken cancellationToken = default);
  ValueTask UploadFileAsync(Stream source, string remoteFilePath, CancellationToken cancellationToken);
  ValueTask UploadFileAsync(Stream source, string remoteFilePath, bool overwrite = false, UnixFilePermissions createPermissions = DefaultCreateFilePermissions, CancellationToken cancellationToken = default);
  ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, CancellationToken cancellationToken = default);
  ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, UploadEntriesOptions? options, CancellationToken cancellationToken = default);

  ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, CancellationToken cancellationToken);
  ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, bool overwrite = false, CancellationToken cancellationToken = default);
  ValueTask DownloadFileAsync(string remoteFilePath, Stream destination, CancellationToken cancellationToken = default);
  ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, CancellationToken cancellationToken = default);
  ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, DownloadEntriesOptions? options, CancellationToken cancellationToken = default);

  ValueTask<string> GetLinkTargetAsync(string linkPath, CancellationToken cancellationToken = default);
  ValueTask CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default);

  ValueTask<string> GetRealPathAsync(string path, CancellationToken cancellationToken = default);
}
class SftpFile : Stream
{
  ValueTask<FileEntryAttributes> GetAttributesAsync(CancellationToken cancellationToken = default); // No extended attributes are returned.
  ValueTask<FileEntryAttributes> GetAttributesAsync(string[]? filter, CancellationToken cancellationToken = default); // 'filter' determines what extended attributes are returned. Set to 'null' to return all.
  ValueTask SetAttributesAsync(
    UnixFilePermissions? permissions = default,
    (DateTimeOffset LastAccess, DateTimeOffset LastWrite)? times = default,
    long? length = default,
    (int Uid, int Gid)? ids = default,
    IEnumerable<KeyValuePair<string, Memory<byte>>>? extendedAttributes = default,
    CancellationToken cancellationToken = default);

  // Read/write at an offset. This does NOT update the offset tracked by the instance.
  ValueTask WriteAtAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken = default);
  ValueTask<int> ReadAtAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken = default);

  ValueTask<long> GetLengthAsync(CancellationToken cancellationToken = default);
  ValueTask SetLengthAsync(long length, CancellationToken cancellationToken = default);

  ValueTask CloseAsync(CancellationToken cancellationToken = default);
}
class SshClientSettings
{
  static IReadOnlyList<Credential> DefaultCredentials { get; }
    = [ PrivateKeyCredential("~/.ssh/id_ed25519"),
        PrivateKeyCredential("~/.ssh/id_ecdsa"),
        PrivateKeyCredential("~/.ssh/id_rsa"),
        CertificateCredential("~/.ssh/id_ed25519-cert.pub", PrivateKeyCredential("~/.ssh/id_ed25519")),
        CertificateCredential("~/.ssh/id_ecdsa-cert.pub", PrivateKeyCredential("~/.ssh/id_ecdsa")),
        CertificateCredential("~/.ssh/id_rsa-cert.pub", PrivateKeyCredential("~/.ssh/id_rsa")),
        SshAgentCredentials(),
        KerberosCredential(),
        NoCredential() ]
  static IReadOnlyList<string> DefaultUserKnownHostsFilePaths { get; } = [ '~/.ssh/known_hosts' ]
  static IReadOnlyList<string> DefaultGlobalKnownHostsFilePaths { get; } = [ '/etc/ssh//etc/ssh/ssh_known_hosts', '/etc/ssh/etc/ssh/ssh_known_hosts2' ]

  SshClientSettings();
  SshClientSettings(string destination);

  TimeSpan ConnectTimeout { get; set; } // = 15s

  string UserName { get; set; } = Environment.UserName;
  string HostName { get; set; } = "";
  int Port { get; set; } = 22;

  List<Credential> Credentials { get; set; } = DefaultCredentials;

  bool AutoConnect { get; set; } = true;
  bool AutoReconnect { get; set; } = false;

  bool TcpKeepAlive { get; set; } = true;
  TimeSpan KeepAliveInterval { get; set; } = TimeSpan.Zero;
  int KeepAliveCountMax { get; set; } = 3;

  Proxy? Proxy { get; set; } = null;

  List<string> GlobalKnownHostsFilePaths { get; set; } = DefaultGlobalKnownHostsFilePaths;
  List<string> UserKnownHostsFilePaths { get; set; } = DefaultUserKnownHostsFilePaths;
  HostAuthentication? HostAuthentication { get; set; } // not called when known to be trusted/revoked.
  bool UpdateKnownHostsFileAfterAuthentication { get; set; } = false;
  bool HashKnownHosts { get; set; } = false;
  bool BatchMode { get; set; } = false;
  bool EnableBatchModeWhenConsoleIsRedirected { get; set; } = true;

  int MinimumRSAKeySize { get; set; } = 2048;

  Dictionary<string, string> EnvironmentVariables { get; set; } = [];
}
class SshConfigSettings
{
  static SshConfigSettings DefaultConfig { get; }  // use DefaultConfigFilePaths.
  static SshConfigSettings NoConfig { get; } // use [ ]
  static IReadOnlyList<string> DefaultConfigFilePaths { get; } // [ '~/.ssh/config', '/etc/ssh/ssh_config' ]

  List<string> ConfigFilePaths { get; set; } = DefaultConfigFilePaths;
  Dictionary<SshConfigOption, SshConfigOptionValue> Options { get; set; }

  TimeSpan ConnectTimeout { get; set; } // = 15s, overridden by config timeout (if set)

  bool AutoConnect { get; set; } = true;
  bool AutoReconnect { get; set; } = false;

  HostAuthentication? HostAuthentication { get; set; } // Called for Unknown when StrictHostKeyChecking is 'ask' (default)
  PasswordPrompt? PasswordPrompt { get; set; } // Called for PasswordAuthentication
}
enum SshConfigOption
{
    Hostname,
    User,
    Port,
    ConnectTimeout,
    GlobalKnownHostsFile,
    UserKnownHostsFile,
    HashKnownHosts,
    StrictHostKeyChecking,
    PreferredAuthentications,
    PubkeyAuthentication,
    IdentityFile,
    GSSAPIAuthentication,
    GSSAPIDelegateCredentials,
    GSSAPIServerIdentity,
    RequiredRSASize,
    SendEnv,
    Ciphers,
    HostKeyAlgorithms,
    KexAlgorithms,
    MACs,
    PubkeyAcceptedAlgorithms,
    TCPKeepAlive,
    ServerAliveCountMax,
    ServerAliveInterval,
    IdentitiesOnly,
    ProxyJump,
    CASignatureAlgorithms,
    CertificateFile,
    PasswordAuthentication,
    BatchMode
}
struct SshConfigOptionValue
{
    SshConfigOptionValue(string value);
    SshConfigOptionValue(IEnumerable<string> values);
    static implicit operator SshConfigOptionValue(string value);

    bool IsEmpty { get; }
    bool IsSingleValue { get; }
    string? FirstValue { get; }
    IEnumerable<string> Values { get; }
}
class SftpClientOptions
{ }
class SftpException : IOException
{
  SftpError Error { get; }
}
enum SftpError
{
  None,
  Eof,
  NoSuchFile,
  PermissionDenied,
  Failure,
  BadMessage,
  Unsupported
}
[Flags]
enum OpenMode
{
  Default = 0,
  Append,
  Truncate
}
class FileEntryAttributes
{
  long Length { get; set; }
  int Uid { get; set; }
  int Gid { get; set; }
  UnixFileType FileType { get; set; }
  UnixFilePermissions Permissions { get; set; }
  DateTimeOffset LastAccessTime { get; set; }
  DateTimeOffset LastWriteTime { get; set; }
  Dictionary<string, byte[]>? ExtendedAttributes { get; set; }
}
class FileOpenOptions
{
  OpenMode OpenMode { get; set; } = OpenMode.Default;

  UnixFilePermissions CreatePermissions { get; set; }; = SftpClient.DefaultCreateFilePermissions;

  // Length is cached. Enables using 'Stream.Length'/'Stream.Seek'.
  bool CacheLength { get; set; } = false;
  // Sets FileStream.CanSeek.
  bool Seekable { get; set; } = false;
}
class EnumerationOptions
{
  bool RecurseSubdirectories { get; set; } = false;
  bool FollowFileLinks { get; set; } = true;
  bool FollowDirectoryLinks { get; set; } = true;
  UnixFileTypeFilter FileTypeFilter { get; set; } = RegularFile | Directory | SymbolicLink | CharacterDevice | BlockDevice | Socket | Fifo;
  SftpFileEntryPredicate? ShouldRecurse { get; set; }
  SftpFileEntryPredicate? ShouldInclude { get; set; }
  string[]? ExtendedAttributes { get; set; } = []; // Extended attributes to return. Set to 'null' to return all.
}
class DownloadEntriesOptions
{
  delegate ReadOnlySpan<char> ReplaceCharacters(ReadOnlySpan<char> invalidPath, ReadOnlySpan<char> invalidChars, Span<char> buffer);

  bool Overwrite { get; set; } = false;
  TargetDirectoryCreation TargetDirectoryCreation { get; set; } = TargetDirectoryCreation.CreateWithParents;
  bool IncludeSubdirectories { get; set; } = true;
  bool FollowFileLinks { get; set; } = true;
  bool FollowDirectoryLinks { get; set; } = true;
  UnixFileTypeFilter FileTypeFilter { get; set; } = RegularFile | Directory | SymbolicLink;
  SftpFileEntryPredicate? ShouldRecurse { get; set; }
  SftpFileEntryPredicate? ShouldInclude { get; set; }
  ReplaceCharacters ReplaceInvalidCharacters { get; set; } = ReplaceInvalidCharactersWithUnderscore;
}
enum TargetDirectoryCreation
{
    None,
    Create,
    CreateWithParents,
    CreateNew,
}
class UploadEntriesOptions
{
  bool Overwrite { get; set; } = false;
  TargetDirectoryCreation TargetDirectoryCreation { get; set; } = TargetDirectoryCreation.CreateWithParents;
  bool IncludeSubdirectories { get; set; } = true;
  bool FollowFileLinks { get; set; } = true;
  bool FollowDirectoryLinks { get; set; } = true;
  LocalFileEntryPredicate? ShouldRecurse { get; set; }
}
delegate T SftpFileEntryTransform<T>(ref SftpFileEntry entry);
delegate bool SftpFileEntryPredicate(ref SftpFileEntry entry);
ref struct SftpFileEntry
{
  long Length { get; }
  int Uid { get; }
  int Gid { get; }
  UnixFileType FileType { get; }
  UnixFilePermissions Permissions { get; }
  DateTimeOffset LastAccessTime { get; }
  DateTimeOffset LastWriteTime { get; }
  ReadOnlySpan<char> Path { get; }
  ReadOnlySpan<char> FileName { get; }

  FileEntryAttributes ToAttributes();
  string ToPath();
}
delegate bool LocalFileEntryPredicate(ref LocalFileEntry entry);
ref struct LocalFileEntry
{
    string ToFullPath();
}
enum UnixFileType
{
  RegularFile,
  Directory,
  SymbolicLink,
  CharacterDevice,
  BlockDevice,
  Socket,
  Fifo,
  WeirdFile
}
[Flags]
enum UnixFileTypeFilter
{
  RegularFile,
  Directory,
  SymbolicLink,
  CharacterDevice,
  BlockDevice,
  Socket,
  Fifo,
  WeirdFile
}
[Flags]
enum UnixFilePermissions // values match System.IO.UnixFileMode.
{
  None,
  OtherExecute,
  OtherWrite,
  OtherRead,
  GroupExecute,
  GroupWrite,
  GroupRead,
  UserExecute,
  UserWrite,
  UserRead,
  StickyBit,
  SetGroup,
  SetUser,
}
static class UnixFilePermissionsExtensions
{
  static UnixFilePermissions ToUnixFilePermissions(this System.IO.UnixFileMode mode);
  static System.IO.UnixFileMode ToUnixFileMode(this UnixFilePermissions permissions);
}
class HostKey
{
  PublicKey Key { get; }
  HostCertificateInfo? CertificateInfo { get; }
}
class HostCertificateInfo
{
  PublicKey IssuerKey { get; }
  string Type { get; }
  ulong SerialNumber { get; }
  string Identifier { get; }
}
class PublicKey
{
  string Type { get; }
  string SHA256FingerPrint { get; }
  string ToString(); // format matches the known_hosts representation.
}
enum KnownHostResult
{
  Trusted,
  Revoked,
  Changed,
  Unknown,
}
struct HostAuthenticationContext
{
  SshConnectionInfo ConnectionInfo { get; }
  KnownHostResult KnownHostResult { get; }
  bool IsBatchMode { get; } // In BatchMode the HostAuthentication delegate mustn't make interactive prompts.
}
delegate ValueTask<bool> HostAuthentication(HostAuthenticationContext context, CancellationToken cancellationToken);
class SshConnectionInfo
{
  HostKey ServerKey { get; }
  string UserName { get; }
  string HostName { get; }
  int Port { get; }
  bool IsProxy { get; }
}
// Base class for all credentials.
abstract class Credential
{ }
class PrivateKeyCredential : Credential
{
  PrivateKeyCredential(string path, string? password = null, string? identifier ??= path);
  PrivateKeyCredential(string path, Func<string?> passwordPrompt, bool queryKey = true, string? identifier ??= path);

  PrivateKeyCredential(char[] rawKey, string? password = null, string identifier = "[raw key]");
  PrivateKeyCredential(char[] rawKey, Func<string?> passwordPrompt, bool queryKey = true, string identifier = "[raw key]");

  // Enable derived classes to use private keys from other sources.
  protected PrivateKeyCredential(Func<CancellationToken, ValueTask<Key>> loadKey, string identifier);
  protected struct Key
  {
    Key(RSA rsa);
    Key(ECDsa ecdsa);
    Key(ReadOnlyMemory<char> rawKey, string? password = null);
    Key(ReadOnlyMemory<char> rawKey, Func<string?> passwordPrompt, bool queryKey = true);
  }
}
class CertificateCredential : Credential
{
  CertificateCredential(string path, PrivateKeyCredential privateKey);
}
delegate ValueTask<string?> PasswordPrompt(PasswordPromptContext context, CancellationToken cancellationToken);
struct PasswordPromptContext
{
  int Attempt { get; }
  SshConnectionInfo ConnectionInfo { get; }
  bool IsBatchMode { get; } // In BatchMode the PasswordPrompt delegate mustn't make interactive prompts.
}
class PasswordCredential : Credential
{
  PasswordCredential(string password);
  PasswordCredential(PasswordPrompt passwordPrompt);
}
class KerberosCredential : Credential
{
  KerberosCredential(NetworkCredential? credential = null, bool delegateCredential = false, string? targetName = null);
}
class SshAgentCredentials : Credential
{
  SshAgentCredentials();
}
class NoCredential : Credential
{
  NoCredential();
}
class Proxy
{
  static Proxy? Chain(params Proxy[] proxies);
}
class SshProxy : Proxy
{
  SshProxy(string destination);
  SshProxy(SshClientSettings settings);
  SshProxy(string destination, SshConfigSettings configSettings);
}
// Base class.
class SshException : Exception
{ }
static class SignalName
{
  const string TERM;
  // ...
}
// Channel operation failed, channel is closed.
class SshChannelException : SshException
{ }
// Channel already closed. InnerException contains reason.
class SshChannelClosedException : SshChannelException
{ }
// SshClient encountered an error, connection is closed.
class SshConnectionException : SshException
{ }
// Connection already closed. InnerException contains reason when closed due to failure.
class SshConnectionClosedException : SshConnectionException
{ }
```

## Algorithms

This section lists the currently supported algorithms. If you would like support for other algorithms, you can request it with an issue in the repository. If the requested algorithm is considered insecure by current practice, it is unlikely to be added.

Supported private key formats*:
- RSA, ECDSA, ED25519 in `OPENSSH PRIVATE KEY` (`openssh-key-v1`) with encryption:
  - none
  - aes[128|192|256]-[cbc|ctr]
  - aes[128|256]-gcm@openssh.com
  - chacha20-poly1305@openssh.com

Supported client key algorithms:
- ssh-ed25519-cert-v01@openssh.com
- ecdsa-sha2-nistp521-cert-v01@openssh.com
- ecdsa-sha2-nistp384-cert-v01@openssh.com
- ecdsa-sha2-nistp256-cert-v01@openssh.com
- rsa-sha2-512-cert-v01@openssh.com
- rsa-sha2-256-cert-v01@openssh.com
- ssh-ed25519
- ecdsa-sha2-nistp521
- ecdsa-sha2-nistp384
- ecdsa-sha2-nistp256
- rsa-sha2-512
- rsa-sha2-256

Supported server key algorithms:
- ssh-ed25519-cert-v01@openssh.com
- ecdsa-sha2-nistp521-cert-v01@openssh.com
- ecdsa-sha2-nistp384-cert-v01@openssh.com
- ecdsa-sha2-nistp256-cert-v01@openssh.com
- rsa-sha2-512-cert-v01@openssh.com
- rsa-sha2-256-cert-v01@openssh.com
- ssh-ed25519
- ecdsa-sha2-nistp521
- ecdsa-sha2-nistp384
- ecdsa-sha2-nistp256
- rsa-sha2-512
- rsa-sha2-256

Supported key exchange methods:
- mlkem768x25519-sha256
- sntrup761x25519-sha512, sntrup761x25519-sha512@openssh.com
- curve25519-sha256, curve25519-sha256@libssh.org
- ecdh-sha2-nistp256
- ecdh-sha2-nistp384
- ecdh-sha2-nistp521

Supported encryption algorithms:
- aes256-gcm@openssh.com
- aes128-gcm@openssh.com
- chacha20-poly1305@openssh.com

Supported message authentication code algorithms:
- none

Supported compression algorithms:
- none

Authentications:
- publickey (`PrivateKeyCredential`)
- publickey from SSH Agent (`SshAgentCredentials`)
- publickey with OpenSSH certificate (`CertificateCredential`)
- password (`PasswordCredential`)
- gssapi-with-mic (`KerberosCredential`)
- none (`NoCredential`)

*: Please convert your keys (using `ssh-keygen`, `PuttyGen`, ...) to a supported format rather than suggesting the library should support an additional format. If you can motivate why the library should support a additional format, open an issue to request support.

## Design

* Since SSH is a network protocol, the APIs are asynchronous and implemented using C# `async` and .NET's `Task`/`ValueTask`.

* For cryptographic algorithms, we use the BCL (.NET base classes) when available and otherwise we use a 3rd party library ([Bouncy Castle.NET](https://github.com/bcgit/bc-csharp)). For security reasons, we avoid implementing cryptographic algorithms ourselves*.

* The library aims to solve common SSH client use-cases similar to functionality offered by CLI tools like `ssh` and `sftp`. We do not provide an API at the SSH protocol level that enables sending custom messages or provide APIs to enable custom encryption algorithms. Such APIs are required only for a small set of use-cases but require a much larger API surface to be maintained. By keep this API internal, we are free to change it.

* SSH cryptographic algorithms continue to evolve. We aim to enable connectivity with SSH servers that (by current standards) support a secure set of algorithms. We do not add support for older (less secure/insecure) algorithms that should no longer be used.

* Performance is a goal. We aim to minimize allocations by using modern .NET primitives like `Span`. For SSH operations, we try to minimize latency and maximize throughput.

* Besides the SSH connection, SSH applications must deal with private keys, known hosts, connection configuration, ... The library supports using [OpenSSH](https://www.openssh.com/) file formats to deal with these concerns. This provides a familiar mechanism to developers and end-users that is compatible with the OpenSSH software stack. Using the OpenSSH formats is optional, developers can choose implement their own configuration.

*: (For historic reasons) some cryptographic algorithms are included for decoding private key files. We don't consider these to impact security in any way.

## Logging

The library supports logging through `Microsoft.Extensions.Logging`.

In production, the log level should be set to `Information` or higher.

Under these levels, the logged messages may include:
- usernames
- hostnames
- key types
- authentication methods
- public keys
- file paths (including those of private keys)

The `Debug` and `Trace` loglevels should not be used in production. Under the `Trace` level all packets are logged. This will expose sensitive data related to the SSH connection and the application itself.

To use logging, create an `ILoggerFactory` and pass it to the `SshClient` constructor.

```cs
using Microsoft.Extensions.Logging;
using Tmds.Ssh;

using ILoggerFactory loggerFactory = LoggerFactory.Create(builder => builder.AddConsole()); // From Microsoft.Extensions.Logging.Console
using var sshClient = new SshClient(..., loggerFactory);
```

## CI Feed

You can obtain packages from the CI NuGet feed: https://www.myget.org/F/tmds/api/v3/index.json.
