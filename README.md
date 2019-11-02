# API

```cs
class SshClient : IAsyncDisposable
{
    SshClient(string destination, Credential? credential = new IdentityFileCredential(), Action<SshClientSettings>? configure = null);
    SshClient(SshClientSettings settings);

    CancellationToken ConnectionClosed { get; }

    Task ConnectAsync(CancellationToken cancellationToken = default);

    Task<ChannelDataStream> CreateTcpConnectionAsStreamAsync(string host, int port, CancellationToken cancellationToken = default);
    Task<ChannelDataStream> CreateTcpConnectionAsStreamAsync(string host, int port, IPAddress originatorIP, int originatorPort, CancellationToken cancellationToken = default);
}

class ChannelDataStream : Stream
{
    ValueTask WriteAsync(ReadOnlyMemory<byte> buffer);
    ValueTask<int> ReadAsync(Memory<byte> buffer);
    void Abort();   // Stops the channel immediately, on-going operations are cancelled.
    void Dispose(); // Calls Abort and frees channel resources.
}

class SshClientSettings
{
    SshClientSettings(string userName, string host, Credential? credential = null);
    TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);
    string UserName { get; }
    string Host { get; }
    int Port { get; set; } = 22;
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