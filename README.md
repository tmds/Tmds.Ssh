# Public API

```cs
class SshClient : IAsyncDisposable
{
    public SshClient(string destination, Credential? credential = new IdentityFileCredential(), Action<SshClientSettings>? configure = null);
    public SshClient(SshClientSettings settings);

    CancellationToken ConnectionClosed { get; }

    Task ConnectAsync(CancellationToken cancellationToken = default);

    Task<Stream> CreateTcpConnectionAsStreamAsync(string host, int port);
    Task<Stream> CreateTcpConnectionAsStreamAsync(string host, int port, IPAddress originatorIP, int originatorPort);
}

public class SshClientSettings
{
    public SshClientSettings(string userName, string host, Credential? credential = null);
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);
    public string UserName { get; }
    public string Host { get; }
    public int Port { get; set; } = 22;
    public List<Credential> Credentials { get; }
}

public class IdentityFileCredential : Credential
{
    public IdentityFileCredential();
    public IdentityFileCredential(string filename);
}

public class PasswordCredential : Credential
{
    public PasswordCredential(string password);
}
```