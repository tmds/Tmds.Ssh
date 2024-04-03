# Tmds.Ssh

.NET SSH client library that wraps [libssh](https://www.libssh.org/).

# Trying the library

You can obtain `Tmds.Ssh` from the CI NuGet feed:
```
dotnet add package Tmds.Ssh --prerelease --source https://www.myget.org/F/tmds/api/v3/index.json
```

`Tmds.Ssh` requires the native `libssh` library.

`libssh` is available on most FOSS operating systems.

Unfortunately `Tmds.Ssh` requires features that are not yet in a released version of `libssh`.
To try `Tmds.Ssh` you must build the `libssh` from source. You can find the source code and build instructions at [libssh INSTALL](https://gitlab.com/libssh/libssh-mirror/-/blob/master/INSTALL).
When the library is built you can use it with `Tmds.Ssh` by setting the `LIBSSH_PATH` environment variable to the `libssh.so`/`libssh.dll` file path.

If you are using Windows on x64, you can obtain a prebuilt `libssh` by using the following package:
```
dotnet add package libssh.win-x64 --prerelease --source https://www.myget.org/F/tmds/api/v3/index.json
```

**Important!**: The `libssh.win-x64` is built to enable running the `Tmds.Ssh` tests on Windows. You must **not** use it in production.

# Getting Started

Create a new Console application:
```sh
dotnet new console -o example
cd example
dotnet add package Tmds.Ssh --version "*-*" --source https://www.myget.org/F/tmds
```

Update `Program.cs`:
```cs
static async Task Main(string[] args)
{
  using var sshClient = new SshClient("localhost");
  await sshClient.ConnectAsync();
  using var process = await sshClient.ExecuteAsync("echo 'hello world!'");
  (_, string line) = await process.ReadLineAsync();
  Console.WriteLine(line);
}
```

Now run the application:
```sh
$ dotnet run
hello world!
```

## API

```cs
namespace Tmds.Ssh;

class SshClient : IDisposable
{
  SshClient(string destination);
  SshClient(SshClientSettings clientSettings);

  Task ConnectAsync(CancellationToken cancellationToken);

  Task<RemoteProcess> ExecuteAsync(string command, CancellationToken cancellationToken);
  Task<RemoteProcess> ExecuteAsync(string command, ExecuteOptions? options = null, CancellationToken cancellationToken = default);

  Task<SshDataStream> OpenTcpConnectionAsync(string host, int port, CancellationToken cancellationToken = default);
  Task<SshDataStream> OpenUnixConnectionAsync(string path, CancellationToken cancellationToken = default);

  Task<SftpClient> CreateSftpClientAsync(CancellationToken cancellationToken = default);
}
class ExecuteOptions
{
  Encoding StandardInputEncoding { get; set; }
  Encoding StandardErrorEncoding { get; set; }
  Encoding StandardOutputEncoding { get; set; }
}
class RemoteProcess : IDisposable
{
  // Read from the remote process.
  ValueTask<(bool isError, string? line)> ReadLineAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default);
  ValueTask<(string? stdout, string? stderr)> ReadToEndAsStringAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default);
  IAsyncEnumerable<(bool isError, string line)> ReadAllLinesAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default);
  ValueTask ReadToEndAsync(Stream? stdoutStream, Stream? stderrStream, CancellationToken? cancellationToken);
  ValueTask<(bool isError, int bytesRead)> ReadAsync(Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken cancellationToken = default);
  ValueTask ReadToEndAsync(Func<Memory<byte>, object, CancellationToken, ValueTask> handleStdout, object? stdoutContext, Func<Memory<byte>, object, CancellationToken, ValueTask> handleStderr, object? stderrContext, CancellationToken? cancellationToken);

  // Write to the remote process.
  ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default);
  ValueTask WriteAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default);
  ValueTask WriteAsync(string value, CancellationToken cancellationToken = default);
  ValueTask WriteLineAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default);
  ValueTask WriteLineAsync(string? value, CancellationToken cancellationToken = default);
  Stream StandardInputStream { get; }
  StreamWriter StandardInputWriter { get; }

  // Wait for the remote process to exit.
  ValueTask WaitForExitAsync(CancellationToken cancellationToken);

  // CancellationToken that cancels when remote process terminates.
  CancellationToken ExecutionAborted { get; }

  // Exit code.
  int ExitCode { get; }
}
class SshDataStream : Stream
{
  CancellationToken StreamAborted { get; }
}
class SftpClient : IDisposable
{
  ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default);
  ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, UnixFilePermissions createPermissions, CancellationToken cancellationToken = default);
  ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, OpenMode mode, CancellationToken cancellationToken = default);
  ValueTask<SftpFile> OpenOrCreateFileAsync(string path, FileAccess access, OpenMode mode, UnixFilePermissions createPermissions, CancellationToken cancellationToken = default);
  ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default);
  ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, UnixFilePermissions permissions, CancellationToken cancellationToken = default);
  ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, OpenMode mode, UnixFilePermissions permissions, CancellationToken cancellationToken = default);
  ValueTask<SftpFile> CreateNewFileAsync(string path, FileAccess access, OpenMode mode, CancellationToken cancellationToken = default);

  // Returns null if the file does not exist.
  ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, CancellationToken cancellationToken = default);
  // Returns null if the file does not exist.
  ValueTask<SftpFile?> OpenFileAsync(string path, FileAccess access, OpenMode mode, CancellationToken cancellationToken = default);

  // Does not throw if the path did not exist.
  ValueTask DeleteFileAsync(string path, CancellationToken cancellationToken = default);

  // Does not throw if the path is an existing directory, or a link to one.
  ValueTask CreateDirectoryAsync(string path, CancellationToken cancellationToken = default);
  ValueTask CreateDirectoryAsync(string path, UnixFilePermissions createPermissions, CancellationToken cancellationToken = default);
  ValueTask CreateDirectoryAsync(string path, bool createParents, CancellationToken cancellationToken = default);
  ValueTask CreateDirectoryAsync(string path, bool createParents, UnixFilePermissions createPermissions, CancellationToken cancellationToken = default);
  // Throws if the path exists.
  ValueTask CreateNewDirectoryAsync(string path, CancellationToken cancellationToken = default);
  ValueTask CreateNewDirectoryAsync(string path, UnixFilePermissions permissions, CancellationToken cancellationToken = default);
  ValueTask CreateNewDirectoryAsync(string path, bool createParents, CancellationToken cancellationToken = default);
  ValueTask CreateNewDirectoryAsync(string path, bool createParents, UnixFilePermissions permissions, CancellationToken cancellationToken = default);

  // Does not throw if the path did not exist.
  ValueTask DeleteDirectoryAsync(string path, CancellationToken cancellationToken = default);

  ValueTask RenameAsync(string oldpath, string newpath, CancellationToken cancellationToken = default);

  ValueTask<FileEntryAttributes?> GetAttributesAsync(string path, bool followLinks = true, CancellationToken cancellationToken = default);
  
  IAsyncEnumerable<(string Path, FileEntryAttributes Attributes)> GetDirectoryEntriesAsync(string path, EnumerationOptions? options = null);
  IAsyncEnumerable<T> GetDirectoryEntriesAsync<T>(string path, SftpFileEntryTransform<T> transform, EnumerationOptions? options = null);

  ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, CancellationToken cancellationToken = default);
  ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, UnixFilePermissions permissions, CancellationToken cancellationToken = default);
  ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite, CancellationToken cancellationToken = default);
  ValueTask UploadFileAsync(string localFilePath, string remoteFilePath, bool overwrite, UnixFilePermissions createPermissions, CancellationToken cancellationToken = default);
  ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, CancellationToken cancellationToken = default);
  ValueTask UploadDirectoryEntriesAsync(string localDirPath, string remoteDirPath, UploadEntriesOptions? options, CancellationToken cancellationToken = default);

  ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, CancellationToken cancellationToken = default);
  ValueTask DownloadFileAsync(string remoteFilePath, string localFilePath, bool overwrite, CancellationToken cancellationToken = default);
  ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, CancellationToken cancellationToken = default);
  ValueTask DownloadDirectoryEntriesAsync(string remoteDirPath, string localDirPath, DownloadEntriesOptions? options, CancellationToken cancellationToken = default);

  ValueTask<string> GetLinkTargetAsync(string linkPath, CancellationToken cancellationToken = default);
  ValueTask CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default);

  ValueTask<string> GetFullPathAsync(string path, CancellationToken cancellationToken = default);

  CancellationToken ClientAborted { get; }
}
class SftpFile : Stream
{
  ValueTask<FileEntryAttributes> GetAttributesAsync(CancellationToken cancellationToken = default);

  // Read/write at an offset. This does NOT update the offset tracked by the instance.
  ValueTask WriteAtAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken = default);
  ValueTask<int> ReadAtAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken = default);

  ValueTask CloseAsync(CancellationToken cancellationToken = default);
}
class SshClientSettings
{
  SshClientSettings();
  SshClientSettings(string destination);
  string? KnownHostsFilePath { get; set; }
  TimeSpan ConnectTimeout { get; set; }
  string UserName { get; set; }
  string Host { get; set; }
  int Port { get; set; }
  List<Credential> Credentials { get; }
  bool CheckGlobalKnownHostsFile { get; set; }
  KeyVerification? KeyVerification { get; set; }
}
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
    None,
    Append,
    Truncate
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
}
class FileEntryAttributes
{
    long? Length { get; set; }
    int? Uid { get; set; }
    int? Gid { get; set; }
    UnixFileType? FileType { get; set; }
    UnixFilePermissions? Permissions { get; set; }
    DateTimeOffset? LastAccessTime { get; set; }
    DateTimeOffset? LastWriteTime { get; set; }
    Dictionary<string, string>? ExtendedAttributes { get; set; }
}
class EnumerationOptions
{
    bool RecurseSubdirectories { get; set; } = false;
    bool FollowFileLinks { get; set; } = true;
    bool FollowDirectoryLinks { get; set; } = true;
    UnixFileTypeFilter FileTypeFilter { get; set; } = RegularFile | Directory | SymbolicLink | CharacterDevice | BlockDevice | Socket | Fifo;
    SftpFileEntryPredicate? ShouldRecurse { get; set; }
    SftpFileEntryPredicate? ShouldInclude { get; set; }
}
class DownloadEntriesOptions
{
    bool Overwrite { get; set; } = false;
    bool RecurseSubdirectories { get; set; } = true;
    bool FollowFileLinks { get; set; } = true;
    bool FollowDirectoryLinks { get; set; } = true;
    UnixFileTypeFilter FileTypeFilter { get; set; } = RegularFile | Directory | SymbolicLink;
    SftpFileEntryPredicate? ShouldRecurse { get; set; }
    SftpFileEntryPredicate? ShouldInclude { get; set; }   
}
class UploadEntriesOptions
{
    bool Overwrite { get; set; } = false;
    bool RecurseSubdirectories { get; set; } = true;
    bool FollowFileLinks { get; set; } = true;
    bool FollowDirectoryLinks { get; set; } = true;
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
    string ToPath()
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
static class UnixFilePemissionExtensions
{
    static UnixFilePermissions ToUnixFilePermissions(this System.IO.UnixFileMode mode);
    static System.IO.UnixFileMode ToUnixFileMode(this UnixFilePermissions permissions);
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
}
class PublicKey
{
  ReadOnlyMemory<byte> SHA256Hash { get; }
}
enum KeyVerificationResult
{
  Trusted,
  AddKnownHost,
  Revoked,
  Error,
  Changed,
  Unknown,
}
delegate ValueTask<KeyVerificationResult> KeyVerification(KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken);
class SshConnectionInfo
{
  PublicKey ServerKey { get; }
  string Host { get; }
  int Port { get; }
}
// Base class for all credentials.
abstract class Credential
{ }
class PrivateKeyFileCredential : Credential
{
  PrivateKeyFileCredential(string filePath);
  string FilePath { get; }
}
class PasswordCredential : Credential
{
  PasswordCredential(string password);
  PasswordCredential(Func<string?> prompt);
}
// Base class.
class SshException : Exception
{ }
// Operation on SshClient failed.
class SshOperationException : SshException
{ }
// SshClient encountered an error, connection is closed.
class SshSessionException : SshException
{ }
// Connection already closed. InnerException contains reason when closed due to failure.
class SshSessionClosedException : SshSessionException
{ }
```
