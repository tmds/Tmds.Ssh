# Tmds.Ssh

.NET SSH client library that uses [libssh](https://www.libssh.org/).

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
namespace Tmds.Ssh
{
class SshClient : IDisposable
{
  SshClient(string destination, Action<SshClientSettings>? configure = null) { }
  SshClient(SshClientSettings clientSettings) { }

  Task ConnectAsync(CancellationToken cancellationToken) { }

  Task<RemoteProcess> ExecuteAsync(string command, CancellationToken cancellationToken) { }
  Task<RemoteProcess> ExecuteAsync(string command, Action<ExecuteOptions>? configure = null, CancellationToken cancellationToken = default) { }

  Task<SshDataStream> OpenTcpConnectionAsync(string host, int port, CancellationToken cancellationToken = default);
  Task<SshDataStream> OpenUnixConnectionAsync(string path, CancellationToken cancellationToken = default);
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
  ValueTask<(bool isError, string? line)> ReadLineAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default) { }
  ValueTask<(string? stdout, string? stderr)> ReadToEndAsStringAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default) { }
  IAsyncEnumerable<(bool isError, string line)> ReadAllLinesAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default) { }
  ValueTask? ReadToEndAsync(Stream? stdoutStream, Stream? stderrStream, bool? disposeStreams, CancellationToken? cancellationToken) { }
  ValueTask<(bool isError, int bytesRead)> ReadAsync(Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken cancellationToken = default) { }
  ValueTask? ReadToEndAsync(Func<Memory<byte>, object, CancellationToken, ValueTask> handleStdout, object? stdoutContext, Func<Memory<byte>, object, CancellationToken, ValueTask> handleStderr, object? stderrContext, CancellationToken? cancellationToken) { }

  // Write to the remote process.
  ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) { }
  Task WriteAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default) { }
  Task WriteAsync(string value, CancellationToken cancellationToken = default) { }
  Task WriteLineAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default) { }
  Task WriteLineAsync(string? value, CancellationToken cancellationToken = default) { }
  Stream StandardInputStream { get; }
  StreamWriter StandardInputWriter { get; }

  // Wait for the remote process to exit.
  ValueTask WaitForExitAsync(CancellationToken cancellationToken) { }

  // CancellationToken that cancels when remote process terminates.
  CancellationToken ExecutionAborted { get; }

  // Exit code.
  int ExitCode { get; }
}
class SshDataStream : Stream
{
  CancellationToken StreamAborted { get; }
}
class SshClientSettings
{
  SshClientSettings() { }
  string? KnownHostsFile { get; set; }
  TimeSpan ConnectTimeout { get; set; }
  string UserName { get; set; }
  string Host { get; set; }
  int Port { get; set; }
  List<Credential> Credentials { get; }
  bool CheckGlobalKnownHostsFile { get; set; }
  KeyVerification? KeyVerification { get; set; }
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
  PrivateKeyFileCredential(string filename) { }
  string FileName { get; }
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
}
```
