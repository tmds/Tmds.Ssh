# API

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

    // Read a single buffer.
    ValueTask<(ProcessReadType readType, int bytesRead)> ReadAsync(Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken ct = default);

    // Read a single line.
    ValueTask<(ProcessReadType readType, string? line)> ReadLineAsync(bool readStdout = true, bool readStderr = true, CancellationToken ct = default)
}

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