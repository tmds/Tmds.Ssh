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
    int? ExitCode { get; }
    string? ExitSignal { get; }

    void Abort(Exception reason); // Stops the channel immediately, on-going operations throw ChannelAbortedException.

    ValueTask WriteInputAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default);
    ValueTask<(ProcessReadType, int bytesRead)> ReadOutputAsync(Memory<byte> buffer, CancellationToken ct = default);
}

enum ProcessReadType
{
    StandardOutput,
    StandardError,
    StandardOutputEof,
    ProcessExit
}

class ChannelDataStream : Stream
{
    public int MaxWriteLength; // Size hint for calling WriteAsync. Larger buffers are split.
    public int MaxReadLength;  // Size hint for calling ReadAsync.
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