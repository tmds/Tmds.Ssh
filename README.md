# Tmds.Ssh

Tmds.Ssh is a .NET SSH client library. It targets netstandard 2.1 (.NET Core 3.x+) and makes use of the new platform APIs for building high-performance network applications.

The library uses .NET Core cryptographic APIs as much as possible. Functionality that is not available is used from the [Bouncy Castle crypto library](https://github.com/bcgit/bc-csharp).

There is no plan to add additional functionality, but the project is open for contribution :)

# API Overview

Creating a client:
```cs
using var client = new SshClient("user@remotehost");
```

Connecting to the server:
```cs
await client.ConnectAsync();
```

SSH is a multiplexed protocol that allows different operations to be performed simultaneously (e.g. forward a TCP connection and execute a command).
Each operation has a dedicated channel.
The objects that represent an operation that is performed over the SSH connection implement `IDisposable`. The `Dispose` methods releases resources associated with the operation and causes the channel to be closed.

The following operations are supported:

Create a TCP connection on the remote server that gets forwarded to the localhost:
```cs
using ChannelDataStream connection = await client.CreateTcpConnectionAsStreamAsync("www.redhat.com", 80);
```

Connect to a Unix socket on the remote server and forward the connection to the localhost:
```cs
using ChannelDataStream connection = await client.CreateUnixConnectionAsStreamAsync("/tmp/myapp.sock");
```

Executing a command on the remote server:
```cs
using RemoteProcess process = await client.ExecuteCommandAsync("echo hello world");
```

# API Reference

```cs
class SshClient : IDisposable
{
    SshClient(string destination, Action<SshClientSettings>? configure = null);

    CancellationToken ConnectionClosed { get; }

    Task ConnectAsync(CancellationToken ct = default);

    Task<ChannelDataStream> CreateTcpConnectionAsStreamAsync(string host, int port, CancellationToken ct);
    Task<ChannelDataStream> CreateTcpConnectionAsStreamAsync(string host, int port, Action<TcpConnectionOptions>? configure = null, CancellationToken ct = default);

    Task<ChannelDataStream> CreateUnixConnectionAsStreamAsync(string socketPath, CancellationToken ct);
    Task<ChannelDataStream> CreateUnixConnectionAsStreamAsync(string socketPath, Action<UnixConnectionOptions>? configure = null, CancellationToken ct = default);

    Task<RemoteProcess> ExecuteCommandAsync(string command, CancellationToken ct);
    Task<RemoteProcess> ExecuteCommandAsync(string command, Action<ExecuteCommandOptions>? configure = null, CancellationToken ct = default);
}

class RemoteProcess : IDisposable
{
    public int MaxWriteLength; // Size hint for calling WriteAsync. Larger buffers are split.
    public int MaxReadLength;  // Size hint for calling ReadAsync.
    public CancellationToken ChannelAborted;
    public CancellationToken ChannelStopped;

    // Exit information.
    int? ExitCode { get; }
    string? ExitSignal { get; }
    bool HasExited { get; }

    // Stops the channel immediately, on-going operations throw ChannelAbortedException.
    void Abort(Exception reason);

    // Write input.
    ValueTask WriteInputAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default);
    Stream StandardInputStream { get; }
    StreamWriter StandardInputWriter { get; }

    // Read everything till exit.
    // - into a string
    ValueTask<(string? stdout, string? stderr)> ReadToEndAsStringAsync(bool readStdout = true, bool readStderr = true, CancellationToken ct = default);
    // - into a Stream
    ValueTask ReadToEndAsync(Stream? stdoutStream, Stream? stderrStream, bool disposeStreams = true, CancellationToken ct = default);
    // - /dev/null
    ValueTask WaitForExitAsync(CancellationToken ct);
    // - custom Action.
    ValueTask ReadToEndAsync(Func<ReadOnlySequence<byte>, object?, CancellationToken, ValueTask>? handleStdout, object? stdoutContext,
                             Func<ReadOnlySequence<byte>, object?, CancellationToken, ValueTask>? handleStderr, object? stderrContext,
                             CancellationToken ct = default)

    // Read a single buffer.
    ValueTask<(ProcessReadType readType, int bytesRead)> ReadAsync(Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken ct = default);

    // Read a single line.
    ValueTask<(ProcessReadType readType, string? line)> ReadLineAsync(bool readStdout = true, bool readStderr = true, CancellationToken ct = default)
}

// note: additional values may be added to this enum
// a reader should ignore values it doesn't know instead of failing.
enum ProcessReadType
{
    StandardOutput,
    StandardError,
    ProcessExit
}

class ChannelDataStream : Stream
{
    public int MaxWriteLength; // Size hint for calling WriteAsync. Larger buffers are split.
    public int MaxReadLength;  // Size hint for calling ReadAsync.
    public CancellationToken ChannelAborted;
    public CancellationToken ChannelStopped;
    ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default);
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default);
    void Abort(Exception reason);  // Stops the channel immediately, on-going operations throw ChannelAbortedException.
    void Dispose(); // Calls Cancel and frees channel resources.
}

class SshClientSettings
{
    TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);
    List<Credential> Credentials { get; }
    HostKeyVerification HostKeyVerification { get; set; } = HostKeyVerification.TrustAll;
}

class IdentityFileCredential : Credential
{
    IdentityFileCredential(); // use ~/.ssh/id_rsa
    IdentityFileCredential(string filename);
}

class PasswordCredential : Credential
{
    PasswordCredential(string password);
}

class SshKey
{
    SshKey(string type, byte[] key);

    string Type { get; }
    byte[] Key { get; }
}

abstract class HostKeyVerification
{
    static HostKeyVerification TrustAll { get; };

    abstract ValueTask<HostKeyVerificationResult> VerifyAsync(SshConnectionInfo connectionInfo, CancellationToken ct);
}

enum HostKeyVerificationResult
{
    Trusted,
    Distrusted,
    Unknown
}

class SshConnectionInfo
{
    public string Host { get; }
    public int Port { get; }
    public SshKey? SshKey { get; }
}
```