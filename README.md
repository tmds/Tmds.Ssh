# Tmds.Ssh

.NET SSH client library based on [libssh](https://www.libssh.org/).

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
public class SshClient : IDisposable
{
  public SshClient(string destination, Action<SshClientSettings>? configure = null) { }
  public SshClient(SshClientSettings clientSettings) { }

  public Task ConnectAsync(CancellationToken cancellationToken) { }

  public Task<RemoteProcess> ExecuteAsync(string command, CancellationToken cancellationToken) { }
  public Task<RemoteProcess> ExecuteAsync(string command, Action<ExecuteOptions>? configure = null, CancellationToken cancellationToken = default) { }
}
public class ExecuteOptions
{
  public Encoding StandardInputEncoding { get; set; }
  public Encoding StandardErrorEncoding { get; set; }
  public Encoding StandardOutputEncoding { get; set; }
}
public class RemoteProcess : IDisposable
{
  // Read from the remote process.
  public ValueTask<(bool isError, string? line)> ReadLineAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default) { }
  public ValueTask<(string? stdout, string? stderr)> ReadToEndAsStringAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default) { }
  public IAsyncEnumerable<(bool isError, string line)> ReadAllLinesAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default) { }
  public ValueTask? ReadToEndAsync(Stream? stdoutStream, Stream? stderrStream, bool? disposeStreams, CancellationToken? cancellationToken) { }
  public ValueTask<(bool isError, int bytesRead)> ReadAsync(Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken cancellationToken = default) { }
  public ValueTask? ReadToEndAsync(Func<Memory<byte>, object, CancellationToken, ValueTask> handleStdout, object? stdoutContext, Func<Memory<byte>, object, CancellationToken, ValueTask> handleStderr, object? stderrContext, CancellationToken? cancellationToken) { }

  // Write to the remote process.
  public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) { }
  public Task WriteAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default) { }
  public Task WriteAsync(string value, CancellationToken cancellationToken = default) { }
  public Task WriteLineAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default) { }
  public Task WriteLineAsync(string? value, CancellationToken cancellationToken = default) { }
  public Stream StandardInputStream { get; }
  public StreamWriter StandardInputWriter { get; }

  // Wait for the remote process to exit.
  public ValueTask WaitForExitAsync(CancellationToken cancellationToken) { }

  // CancellationToken that cancels when remote process terminates.
  public CancellationToken ExecutionAborted { get; }

  // Exit code.
  public int ExitCode { get; }
}
public class SshClientSettings
{
  public SshClientSettings() { }
  public string? KnownHostsFile { get; set; }
  public TimeSpan ConnectTimeout { get; set; }
  public string UserName { get; set; }
  public string Host { get; set; }
  public int Port { get; set; }
  public List<Credential> Credentials { get; }
  public bool CheckGlobalKnownHostsFile { get; set; }
  public KeyVerification? KeyVerification { get; set; }
}
public class PublicKey
{
  public ReadOnlyMemory<byte> SHA256Hash { get; }
}
public enum KeyVerificationResult
{
  Trusted,
  AddKnownHost,
  Revoked,
  Error,
  Changed,
  Unknown,
}
public delegate ValueTask<KeyVerificationResult> KeyVerification(KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken = default);
public class SshConnectionInfo
{
  public PublicKey ServerKey { get; }
  public string Host { get; }
  public int Port { get; }
}
// Base class for all credentials.
public abstract class Credential
{ }
public class PrivateKeyFileCredential : Credential
{
  public PrivateKeyFileCredential(string filename) { }
  public string FileName { get; }
}
// Base class.
public class SshException : Exception
{ }
// Operation on SshClient failed.
public class SshOperationException : SshException
{ }
// SshClient encountered an error, connection is closed.
public class SshSessionException : SshException
{ }
// Connection already closed. InnerException contains reason when closed due to failure.
public class SshSessionClosedException : SshSessionException
{ }
}
```