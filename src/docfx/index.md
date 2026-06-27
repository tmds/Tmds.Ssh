[![NuGet](https://img.shields.io/nuget/v/Tmds.Ssh.svg)](https://www.nuget.org/packages/Tmds.Ssh)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Tmds.Ssh)](https://www.nuget.org/packages/Tmds.Ssh)
[![GitHub](https://img.shields.io/badge/GitHub-tmds%2FTmds.Ssh-blue?logo=github)](https://github.com/tmds/Tmds.Ssh)
[![License](https://img.shields.io/github/license/tmds/Tmds.Ssh)](https://github.com/tmds/Tmds.Ssh/blob/main/LICENSE)
![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)

## Tmds.Ssh

Tmds.Ssh is a modern, open-source SSH client library for .NET.

**Open Source**
- MIT licensed
- Source code available
- Open for contributions, see below.

**OpenSSH Compatibility**
- Supports OpenSSH private key formats and configuration files
- Compatible with `known_hosts` for host key verification

**Security First**
- Secure cryptographic algorithms (no legacy/insecure algorithms)
- Post-quantum key exchange support
- Uses BCL and Bouncy Castle for cryptography—no custom crypto implementations

**Modern .NET**
- Built from the ground up with C# `async`/`await` and `Task`/`ValueTask` for efficient asynchronous operations
- Optimized for performance with .NET primitives like `Span<T>` to minimize allocations
- Integration with `Microsoft.Extensions.Logging`

### Supported Algorithms

This section lists the supported algorithms. If you would like support for other algorithms, you can request it with [an issue in the repository](https://github.com/tmds/Tmds.Ssh/issues). If the requested algorithm is considered insecure by current practice, it is unlikely to be added.

Private key formats*:
- RSA, ECDSA, ED25519 in `OPENSSH PRIVATE KEY` (`openssh-key-v1`) with encryption:
  - none
  - aes[128|192|256]-[cbc|ctr]
  - aes[128|256]-gcm@openssh.com
  - chacha20-poly1305@openssh.com

Client key algorithms:
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

Server key algorithms:
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

Key exchange methods:
- mlkem768x25519-sha256
- sntrup761x25519-sha512, sntrup761x25519-sha512@openssh.com
- curve25519-sha256, curve25519-sha256@libssh.org
- ecdh-sha2-nistp256
- ecdh-sha2-nistp384
- ecdh-sha2-nistp521

Encryption algorithms:
- aes256-gcm@openssh.com
- aes128-gcm@openssh.com
- chacha20-poly1305@openssh.com

Message authentication code algorithms:
- none

Compression algorithms:
- none

Authentication algorithms:
- publickey (<xref:Tmds.Ssh.PrivateKeyCredential>)
- publickey from SSH Agent (<xref:Tmds.Ssh.SshAgentCredentials>)
- publickey with OpenSSH certificate (<xref:Tmds.Ssh.CertificateCredential>)
- password (<xref:Tmds.Ssh.PasswordCredential>)
- gssapi-with-mic (<xref:Tmds.Ssh.KerberosCredential>)
- none (<xref:Tmds.Ssh.NoCredential>)

*: Please convert your keys (using `ssh-keygen`, `PuttyGen`, ...) to a supported format rather than suggesting the library should support an additional format. If you can motivate why the library should support a additional format, open an issue to request support.

### Reporting Bugs and Contributing

Found a bug or want to request a feature? Please [open an issue on GitHub](https://github.com/tmds/Tmds.Ssh/issues).

For security vulnerabilities, use [GitHub's private security reporting](https://github.com/tmds/Tmds.Ssh/security/advisories/new) instead.

Interested in contributing? We welcome pull requests on [GitHub](https://github.com/tmds/Tmds.Ssh)! Unless you're making a trivial change, open an issue to discuss the change before making a pull request.

## Connecting to an SSH server

The library provides two client types:

- <xref:Tmds.Ssh.SshClient> — for executing remote commands, forwarding connections, and performing filesystem operations.
- <xref:Tmds.Ssh.SftpClient> — for performing filesystem operations using SFTP (SSH File Transfer Protocol).

### Creating an SshClient

The simplest way to create an <xref:Tmds.Ssh.SshClient> is with a destination string in the format `[user@]host[:port]`. This uses the SSH credentials for the current user and validates the server against the OpenSSH `known_hosts` files:

```csharp
using Tmds.Ssh;

using var sshClient = new SshClient("user@example.com");
using var process = await sshClient.ExecuteAsync("echo 'hello world!'");
(bool isError, string? content) = await process.ReadLineAsync();
Console.WriteLine(content);
```

By default, the connection is established automatically when the first operation is performed. You can also connect explicitly by calling <xref:Tmds.Ssh.SshClient.ConnectAsync(System.Threading.CancellationToken)>:

```csharp
using var sshClient = new SshClient("user@example.com");
await sshClient.ConnectAsync();
```

The <xref:Tmds.Ssh.SshClient.Disconnected> property provides a `CancellationToken` that is canceled when the connection is closed — this can be used to detect connection loss when `AutoReconnect` is not enabled.

For full control over the connection, pass an <xref:Tmds.Ssh.SshClientSettings> instance. The following example configures a private key credential and custom host authentication:

```csharp
string destination = "user@example.com";
string privatekeyFile = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh/id_rsa");
string trustedFingerprint = "BkEYx77wOyUBL8UZfgoYKPLkwLJ7XMrsTwAu5sQC4C8";

var settings = new SshClientSettings(destination)
{
    Credentials = [ new PrivateKeyCredential(privatekeyFile) ],
    UserKnownHostsFilePaths = [ ],
    HostAuthentication =
    (HostAuthenticationContext context, CancellationToken cancellationToken) =>
    {
        if (context.ConnectionInfo.ServerKey.Key.SHA256FingerPrint == trustedFingerprint)
        {
            return ValueTask.FromResult(true);
        }
        return ValueTask.FromResult(false);
    }
};

using var sshClient = new SshClient(settings);
```

If your application wants to use OpenSSH config files for configuring host settings, you can pass a <xref:Tmds.Ssh.SshConfigSettings>. Settings such as hostname, port, user, identity files, and proxy configuration are picked up automatically:

```csharp
using var sshClient = new SshClient("myhost", SshConfigSettings.DefaultConfig);
```

<xref:Tmds.Ssh.SshConfigSettings.DefaultConfig> reads the default config file paths. Use <xref:Tmds.Ssh.SshConfigSettings.NoConfig> to skip config files entirely. You can also set options programmatically:

```csharp
var configSettings = new SshConfigSettings()
{
    Options = { [SshConfigOption.IdentityFile] = "/path/to/key" },
};

using var sshClient = new SshClient("myhost", configSettings);
```

### Creating an SftpClient

The connection to the SSH server is always made by the `SshClient`. If your application has an `SshClient` instance, you can open an SFTP session by calling the <xref:Tmds.Ssh.SshClient.OpenSftpClientAsync(System.Threading.CancellationToken)>.

```csharp
// Open an SFTP session on an `SshClient`.
using var sftpClient = await sshClient.OpenSftpClientAsync();
await sftpClient.UploadFileAsync("/local/file.txt", "/remote/file.txt");
```

If your application will only perform SFTP operations, you can directly create an <xref:Tmds.Ssh.SftpClient> and connect it to the server. The `SftpClient` supports the same constructors as the <xref:Tmds.Ssh.SshClient>. Under the hood, the `SftpClient` will use an `SshClient` that establishes the connection.

```csharp
// SftpClient instance owns an SshClient connection.
using var sftpClient = new SftpClient("user@example.com");
await sftpClient.UploadFileAsync("/local/file.txt", "/remote/file.txt");
```

### Client Authentication

The <xref:Tmds.Ssh.SshClientSettings.Credentials> property controls how the client authenticates with the server. When multiple credentials are provided, they are tried in order until one succeeds.

When no credentials are configured explicitly, the client uses these defaults:

- Private keys from `~/.ssh/`: `id_ed25519`, `id_ecdsa`, `id_rsa`
- Matching OpenSSH certificates: `id_ed25519-cert.pub`, `id_ecdsa-cert.pub`, `id_rsa-cert.pub`
- SSH agent keys
- Kerberos
- No authentication

Multiple credentials can be combined. For example, to try a private key first and fall back to a password:

```csharp
var settings = new SshClientSettings("user@example.com")
{
    Credentials = [
        new PrivateKeyCredential("/home/user/.ssh/id_ed25519"),
        new PasswordCredential("password"),
    ],
};
```

When the server requires multi-factor authentication, the library handles this automatically. Each successful step produces a partial result, and the client continues with the remaining credentials until all required methods are satisfied.

#### Private Keys

A <xref:Tmds.Ssh.PrivateKeyCredential> authenticates using a private key file:

```csharp
var settings = new SshClientSettings("user@example.com")
{
    Credentials = [ new PrivateKeyCredential("/home/user/.ssh/id_ed25519") ],
};
```

If the key is encrypted, you can provide the password directly or through a callback. When `queryKey` is `true`, the library checks whether the server accepts the key before prompting for the decryption password:

```csharp
new PrivateKeyCredential("/path/to/key", password: "passphrase")
new PrivateKeyCredential("/path/to/key", passwordPrompt: () => ReadPassword(), queryKey: true)
```

#### SSH Agent Keys

An <xref:Tmds.Ssh.SshAgentCredentials> uses keys managed by an SSH agent:

```csharp
Credentials = [ new SshAgentCredentials() ]
```

#### OpenSSH Certificate Keys

A <xref:Tmds.Ssh.CertificateCredential> authenticates with a private key that is signed by a certificate authority:

```csharp
Credentials = [ new CertificateCredential("/path/to/cert", new PrivateKeyCredential("/path/to/key")) ]
```

#### Password Authentication

A <xref:Tmds.Ssh.PasswordCredential> authenticates with a password. The password can be provided as a string or through a callback:

```csharp
Credentials = [ new PasswordCredential("password") ]
```

The callback receives a <xref:Tmds.Ssh.PasswordPromptContext> with connection info and batch mode state:

```csharp
Credentials = [ new PasswordCredential((context, cancellationToken) =>
{
    if (context.IsBatchMode)
    {
        return ValueTask.FromResult((string?)null);
    }

    string prompt = $"{context.ConnectionInfo.UserName}@{context.ConnectionInfo.HostName}'s password: ";
    Console.Write(prompt);
    return ValueTask.FromResult(Console.ReadLine());
}) ]
```

#### Kerberos Authentication

A <xref:Tmds.Ssh.KerberosCredential> authenticates using Kerberos. When no credential is provided, a cached Kerberos ticket is used. The `delegateCredential` parameter allows the SSH server to act on behalf of the user on remote systems:

```csharp
Credentials = [ new KerberosCredential() ]
Credentials = [ new KerberosCredential(new NetworkCredential("user", "password", "REALM"), delegateCredential: true) ]
```

### Server Authentication

By default, the server's host key is verified against the OpenSSH `known_hosts` files. The <xref:Tmds.Ssh.SshClientSettings.UserKnownHostsFilePaths> and <xref:Tmds.Ssh.SshClientSettings.GlobalKnownHostsFilePaths> properties control which files are used.

For custom verification, set the <xref:Tmds.Ssh.SshClientSettings.HostAuthentication> delegate. The delegate is called when the host key is not found in any known hosts file. It is not called when the key is already known to be trusted or revoked:

```csharp
var settings = new SshClientSettings("user@example.com")
{
    UserKnownHostsFilePaths = [ ],
    HostAuthentication =
    (HostAuthenticationContext context, CancellationToken cancellationToken) =>
    {
        string expected = "BkEYx77wOyUBL8UZfgoYKPLkwLJ7XMrsTwAu5sQC4C8";
        return ValueTask.FromResult(context.ConnectionInfo.ServerKey.Key.SHA256FingerPrint == expected);
    }
};
```

Set <xref:Tmds.Ssh.SshClientSettings.UpdateKnownHostsFileAfterAuthentication> to `true` to add newly accepted host keys to the known hosts file.

When using <xref:Tmds.Ssh.SshConfigSettings>, the <xref:Tmds.Ssh.SshConfigSettings.HostAuthentication> delegate is called for unknown keys when `StrictHostKeyChecking` is `ask` (the default).

### Connection settings

<xref:Tmds.Ssh.SshClientSettings> provides additional properties for controlling the connection:

| Property | Default | Description |
|----------|---------|-------------|
| `ConnectTimeout` | 15 seconds | Maximum duration for establishing an authenticated connection. |
| `AutoConnect` | `true` | Automatically connect on first operation. |
| `AutoReconnect` | `false` | Reconnect automatically after an unexpected disconnect on the next operation. |
| `TcpKeepAlive` | `true` | Enable TCP keep-alive. |
| `KeepAliveInterval` | `TimeSpan.Zero` | Interval between SSH keep-alive messages. |
| `KeepAliveCountMax` | 3 | Max keep-alive messages before disconnecting. |
| `BatchMode` | `false` | Disable interactive prompts. |
| `EnableBatchModeWhenConsoleIsRedirected` | `true` | Automatically enable batch mode when the console is redirected. |
| `MinimumRSAKeySize` | 2048 | Minimum RSA key size accepted. |
| `EnvironmentVariables` | | Environment variables set for all remote processes. |

### Jump hosts

The <xref:Tmds.Ssh.SshClientSettings.Proxy> property enables connecting through an SSH jump host:

```csharp
var settings = new SshClientSettings("target-host")
{
    Proxy = new SshProxy("jump-host"),
};

using var sshClient = new SshClient(settings);
```

Multiple proxies can be chained using <xref:Tmds.Ssh.Proxy.Chain(Tmds.Ssh.Proxy[])>:

```csharp
var settings = new SshClientSettings("target-host")
{
    Proxy = Proxy.Chain(new SshProxy("jump1"), new SshProxy("jump2")),
};
```

### Algorithms

The permitted cryptographic algorithms can be configured through properties like `KeyExchangeAlgorithms`, `ServerHostKeyAlgorithms`, `EncryptionAlgorithmsClientToServer`, and others. Each property accepts an <xref:Tmds.Ssh.AlgorithmList> that specifies the algorithms in preference order.

For example, to restrict key exchange to post-quantum algorithms:

```csharp
var settings = new SshClientSettings("user@example.com")
{
    KeyExchangeAlgorithms = [ "mlkem768x25519-sha256", "sntrup761x25519-sha512" ],
};
```

### Logging

Both <xref:Tmds.Ssh.SshClient> and <xref:Tmds.Ssh.SftpClient> accept an optional `ILoggerFactory` for diagnostic logging through `Microsoft.Extensions.Logging`:

```csharp
using Microsoft.Extensions.Logging;
using Tmds.Ssh;

using ILoggerFactory loggerFactory = LoggerFactory.Create(builder =>
{
    builder.AddConsole();
});

using var sshClient = new SshClient("user@example.com", loggerFactory);
```

In production, the log level should be set to `Information` or higher. The `Debug` and `Trace` levels expose sensitive data including usernames, hostnames, key types, public keys, and file paths. At `Trace` level, all packets are logged.

## Executing Commands, Shells and Subsystems

### Starting a remote process

<xref:Tmds.Ssh.SshClient.ExecuteAsync(System.String,System.Threading.CancellationToken)> runs a command on the remote server and returns a <xref:Tmds.Ssh.RemoteProcess> for interacting with it:

```csharp
using var sshClient = new SshClient("user@example.com");

using var process = await sshClient.ExecuteAsync("echo 'hello world!'");
(bool isError, string? content) = await process.ReadLineAsync();
Console.WriteLine(content);
```

<xref:Tmds.Ssh.SshClient.ExecuteShellAsync(System.Threading.CancellationToken)> and <xref:Tmds.Ssh.SshClient.ExecuteSubsystemAsync(System.String,System.Threading.CancellationToken)> are similar methods for running a shell and a subsystem. They also return a <xref:Tmds.Ssh.RemoteProcess>.

How the server handles commands, shells, and subsystems is server dependent. Typical behavior for executing a command is to use the user's shell to execute it. For a shell, it is to launch the user's default shell as a login shell. A subsystem is a predefined server-side program identified by name, such as `sftp`.

### Reading output

<xref:Tmds.Ssh.RemoteProcess> provides several ways to read standard output and standard error. The simplest is to read all output at once using <xref:Tmds.Ssh.RemoteProcess.ReadToEndAsStringAsync(System.Threading.CancellationToken)>:

```csharp
using var process = await sshClient.ExecuteAsync("hostname");
(string stdout, string stderr) = await process.ReadToEndAsStringAsync();
Console.WriteLine(stdout);
```

To read a single line, use <xref:Tmds.Ssh.RemoteProcess.ReadLineAsync(System.Threading.CancellationToken)>. It returns `null` when the end of the output is reached:

```csharp
using var process = await sshClient.ExecuteAsync("echo 'hello world!'");
(bool isError, string? content) = await process.ReadLineAsync();
Console.WriteLine(content);
```

For line-by-line processing, use <xref:Tmds.Ssh.RemoteProcess.ReadAllLinesAsync(System.Threading.CancellationToken)>:

```csharp
using var process = await sshClient.ExecuteAsync("ls -la");
await foreach ((bool isError, string content) in process.ReadAllLinesAsync())
{
    if (isError)
        Console.Error.WriteLine(content);
    else
        Console.WriteLine(content);
}
```

For reading into a buffer, use <xref:Tmds.Ssh.RemoteProcess.ReadAsync(System.Nullable{System.Memory{System.Byte}},System.Nullable{System.Memory{System.Byte}},System.Threading.CancellationToken)>. To copy all output into a `Stream`, use <xref:Tmds.Ssh.RemoteProcess.ReadToEndAsync(System.IO.Stream,System.IO.Stream,System.Threading.CancellationToken)>. To wrap the output as a `Stream` or `StreamReader`, use <xref:Tmds.Ssh.RemoteProcess.ReadAsStream(Tmds.Ssh.StderrHandler)> or <xref:Tmds.Ssh.RemoteProcess.ReadAsStreamReader(Tmds.Ssh.StderrHandler,System.Int32)>.

### Writing standard input

Data can be written to the process using <xref:Tmds.Ssh.RemoteProcess.WriteAsync(System.String,System.Threading.CancellationToken)>:

```csharp
using var process = await sshClient.ExecuteAsync("cat");
await process.WriteAsync("Hello World!");
process.WriteEof();
(string stdout, string stderr) = await process.ReadToEndAsStringAsync();
Console.WriteLine(stdout);
```

Other write methods include <xref:Tmds.Ssh.RemoteProcess.WriteAsync(System.ReadOnlyMemory{System.Byte},System.Threading.CancellationToken)> for raw bytes, <xref:Tmds.Ssh.RemoteProcess.WriteLineAsync(System.String,System.Threading.CancellationToken)> for writing a line, and <xref:Tmds.Ssh.RemoteProcess.StandardInputStream> and <xref:Tmds.Ssh.RemoteProcess.StandardInputWriter> for stream-based writing.

If you are not writing to standard input, call <xref:Tmds.Ssh.RemoteProcess.WriteEof> early to prevent the remote process from blocking on reading input.

### Getting the exit code

After reading the output, <xref:Tmds.Ssh.RemoteProcess.GetExitCodeAsync(System.Threading.CancellationToken)> returns the exit code. If there is any unread output remaining when this method is called, it will be discarded.

```csharp
using var process = await sshClient.ExecuteAsync("ls /nonexistent");
(string stdout, string stderr) = await process.ReadToEndAsStringAsync();
int exitCode = await process.GetExitCodeAsync();
Console.WriteLine($"Exit code: {exitCode}");
```

<xref:Tmds.Ssh.RemoteProcess.GetExitStatusAsync(System.Threading.CancellationToken)> is similar but returns an <xref:Tmds.Ssh.RemoteProcess.ExitStatus> which includes both the exit code and the signal name (if the process was terminated by a signal):

```csharp
(string stdout, string stderr) = await process.ReadToEndAsStringAsync();
(int exitCode, string? exitSignal) = await process.GetExitStatusAsync();
```

### Detect termination

The <xref:Tmds.Ssh.RemoteProcess.ExecutionAborted> cancellation token is triggered when the remote process can no longer be interacted with. This includes normal process termination and connection loss. It can be used to cancel other operations that depend on the remote process.

### Allocating a Terminal

Some programs need to run with a terminal. To allocate one, set <xref:Tmds.Ssh.ExecuteOptions.AllocateTerminal> to `true`:

```csharp
var options = new ExecuteOptions
{
    AllocateTerminal = true,
    TerminalWidth = 120,
    TerminalHeight = 40,
};

using var process = await sshClient.ExecuteAsync("top", options);
```

The terminal type can be set with <xref:Tmds.Ssh.ExecuteOptions.TerminalType>. You can check whether a terminal was allocated using <xref:Tmds.Ssh.RemoteProcess.HasTerminal>, and resize it with <xref:Tmds.Ssh.RemoteProcess.SetTerminalSize(System.Int32,System.Int32)>.

When a terminal is allocated, standard error is merged into standard output.

### Sending signals

<xref:Tmds.Ssh.RemoteProcess.SendSignal(System.String)> sends a signal to the remote process:

```csharp
process.SendSignal(SignalName.TERM);
```

The <xref:Tmds.Ssh.SignalName> class provides constants for common signal names. The method returns `true` if the signal was sent, or `false` if the signal can no longer be delivered.

## Forwarding Connections

<xref:Tmds.Ssh.SshClient> provides methods for forwarding connections over the SSH connection.

### Forward between endpoints

<xref:Tmds.Ssh.SshClient.StartForwardAsync*> binds a local endpoint and forwards incoming connections to a remote endpoint.

```csharp
using var forward = await sshClient.StartForwardAsync(
    new IPEndPoint(IPAddress.Loopback, 8080),
    new RemoteHostEndPoint("localhost", 80));

Console.WriteLine($"Forwarding on {forward.ListenEndPoint}");
```

The local endpoint can be an `IPEndPoint` or a `UnixDomainSocketEndPoint`. The remote endpoint can be a <xref:Tmds.Ssh.RemoteHostEndPoint>, <xref:Tmds.Ssh.RemoteIPEndPoint>, or <xref:Tmds.Ssh.RemoteUnixEndPoint>.

<xref:Tmds.Ssh.SshClient.StartRemoteForwardAsync*> binds a remote endpoint and forwards incoming connections to a local endpoint.

```csharp
using var forward = await sshClient.StartRemoteForwardAsync(
    new RemoteIPListenEndPoint("localhost", 8080),
    new IPEndPoint(IPAddress.Loopback, 80));
```

The remote endpoint can be a <xref:Tmds.Ssh.RemoteIPListenEndPoint> or a <xref:Tmds.Ssh.RemoteUnixEndPoint>. The local endpoint can be a `DnsEndPoint`, `IPEndPoint`, or `UnixDomainSocketEndPoint`.

The returned <xref:Tmds.Ssh.LocalForward> and <xref:Tmds.Ssh.RemoteForward> implement `IDisposable` — disposing stops the forward. They also expose a `Stopped` cancellation token that triggers when the forward stops (for example, when the SSH connection drops), and `ThrowIfStopped` to check that the forward is still running.

### Proxy via SOCKS

<xref:Tmds.Ssh.SshClient.StartSocksForwardAsync*> starts a local SOCKS proxy that routes traffic through the SSH server.

```csharp
using var proxy = await sshClient.StartSocksForwardAsync(
    new IPEndPoint(IPAddress.Loopback, 1080));

Console.WriteLine($"SOCKS proxy on {proxy.ListenEndPoint}");
```

The returned <xref:Tmds.Ssh.SocksForward> implements `IDisposable` — disposing it stops the forward. It also exposes a <xref:Tmds.Ssh.SocksForward.Stopped> cancellation token that triggers when the forward stops (for example, when the SSH connection drops), and <xref:Tmds.Ssh.SocksForward.ThrowIfStopped> to check that the forward is still running.

### Open a TCP/Unix connection

<xref:Tmds.Ssh.SshClient.OpenTcpConnectionAsync*> opens a direct TCP connection to a host through the SSH server:

```csharp
using var stream = await sshClient.OpenTcpConnectionAsync("database-server", 5432);
```

<xref:Tmds.Ssh.SshClient.OpenUnixConnectionAsync*> connects to a Unix domain socket on the remote server:

```csharp
using var stream = await sshClient.OpenUnixConnectionAsync("/var/run/postgresql/.s.PGSQL.5432");
```

### Listen for TCP/Unix connections

`ListenTcpAsync` creates a TCP listener on the remote server. Incoming connections are accepted through the SSH tunnel as <xref:Tmds.Ssh.RemoteConnection> types:

```csharp
using var listener = await sshClient.ListenTcpAsync("0.0.0.0", 8080);
while (true)
{
    using var connection = await listener.AcceptAsync();
    if (!connection.HasStream)
        break; // Listener was stopped.

    using var stream = connection.MoveStream();
    // Handle the incoming connection...
}
```

When the listener is stopped via <xref:Tmds.Ssh.RemoteListener.Stop>, `AcceptAsync` returns a <xref:Tmds.Ssh.RemoteConnection> with <xref:Tmds.Ssh.RemoteConnection.HasStream> set to `false`. Use <xref:Tmds.Ssh.RemoteConnection.MoveStream> to take ownership of the connection stream.

Pass port `0` to let the server assign a port. The actual assigned port is available from <xref:Tmds.Ssh.RemoteListener.ListenEndPoint>.

<xref:Tmds.Ssh.SshClient.ListenUnixAsync*> does the same for Unix domain sockets:

```csharp
using var listener = await sshClient.ListenUnixAsync("/tmp/my.sock");
```

## SSH File Transfer Protocol (SFTP)

The <xref:Tmds.Ssh.SftpClient> provides methods for performing filesystem operations on remote servers using the SSH File Transfer Protocol (SFTP).

The following example uploads a file to the server and downloads it back:

```csharp
using Tmds.Ssh;

using var sftpClient = new SftpClient("user@example.com");
await sftpClient.UploadFileAsync("/local/path/file.txt", "/remote/path/file.txt");
await sftpClient.DownloadFileAsync("/remote/path/file.txt", "/local/path/downloaded.txt");
```

All SFTP file operations are defined on the <xref:Tmds.Ssh.ISftpDirectory> interface. <xref:Tmds.Ssh.SftpClient> implements this interface using the server's working directory as the base for relative paths. To scope operations to a specific directory, use <xref:Tmds.Ssh.SftpClient.GetDirectory(System.String)>. The returned <xref:Tmds.Ssh.SftpDirectory> implements the same interface, resolving relative paths against the specified directory:

```csharp
SftpDirectory uploads = sftpClient.GetDirectory("/remote/uploads");
await uploads.UploadFileAsync("/local/file.txt", "file.txt");
```

### Uploading files

To upload a file from disk, pass the local and remote paths:

```csharp
await sftpClient.UploadFileAsync("/local/file.txt", "/remote/file.txt");
```

You can also upload from a `Stream`:

```csharp
using var stream = File.OpenRead("/local/report.csv");
await sftpClient.UploadFileAsync(stream, "/remote/report.csv");
```

By default, <xref:Tmds.Ssh.SftpClient.UploadFileAsync*> will not overwrite an existing file. Pass `overwrite: true` to replace it. The `createPermissions` parameter sets the file permissions on the remote server — the server applies a umask on top of these:

```csharp
await sftpClient.UploadFileAsync("/local/file.txt", "/remote/file.txt", overwrite: true,
    createPermissions: UnixFilePermissions.UserRead | UnixFilePermissions.UserWrite);
```

<xref:Tmds.Ssh.SftpClient.UploadDirectoryEntriesAsync*> uploads all entries from a local directory to a remote directory:

```csharp
await sftpClient.UploadDirectoryEntriesAsync("/local/dir", "/remote/dir");
```

<xref:Tmds.Ssh.UploadEntriesOptions> controls overwriting, subdirectory recursion, link following, filtering, and concurrency:

```csharp
await sftpClient.UploadDirectoryEntriesAsync("/local/dir", "/remote/dir",
    new UploadEntriesOptions
    {
        Overwrite = true,
        ShouldInclude = (ref LocalFileEntry entry) => !entry.ToFullPath().EndsWith(".tmp")
    });
```

The <xref:Tmds.Ssh.TargetDirectoryCreation> property controls whether the target directory is created automatically. The default is `CreateWithParents`. `Create` creates only the target directory without parents. Set it to `None` if the target directory must already exist, or `CreateNew` to fail if it already exists.

### Downloading files

To download a file to disk:

```csharp
await sftpClient.DownloadFileAsync("/remote/file.txt", "/local/file.txt");
```

To download into a `Stream`:

```csharp
using var stream = File.Create("/local/file.txt");
await sftpClient.DownloadFileAsync("/remote/file.txt", stream);
```

<xref:Tmds.Ssh.SftpClient.DownloadDirectoryEntriesAsync*> downloads all entries from a remote directory to a local directory:

```csharp
await sftpClient.DownloadDirectoryEntriesAsync("/remote/dir", "/local/dir");
```

<xref:Tmds.Ssh.DownloadEntriesOptions> provides the same controls as <xref:Tmds.Ssh.UploadEntriesOptions>. Download options use <xref:Tmds.Ssh.SftpFileEntryPredicate> for filtering remote entries, while upload options use <xref:Tmds.Ssh.LocalFileEntryPredicate> for filtering local entries:

```csharp
await sftpClient.DownloadDirectoryEntriesAsync("/remote/dir", "/local/dir",
    new DownloadEntriesOptions
    {
        FileTypeFilter = UnixFileTypeFilter.RegularFile,
        ShouldInclude = (ref SftpFileEntry entry) => entry.Length > 0
    });
```

### Copying files

<xref:Tmds.Ssh.SftpClient.CopyFileAsync*> copies a file on the remote server:

```csharp
await sftpClient.CopyFileAsync("/remote/source.txt", "/remote/destination.txt");
```

When the server supports the `copy-data` SFTP extension, the copy is performed entirely server-side. Otherwise, the data is read from the source and written to the destination through the client.

### Renaming files and directories

<xref:Tmds.Ssh.SftpClient.RenameAsync*> renames a file or directory:

```csharp
await sftpClient.RenameAsync("/remote/old.txt", "/remote/new.txt");
```

### Working with directories

<xref:Tmds.Ssh.SftpClient.CreateDirectoryAsync*> creates a directory. Pass `createParents: true` to create intermediate directories:

```csharp
await sftpClient.CreateDirectoryAsync("/remote/path/to/newdir", createParents: true);
```

<xref:Tmds.Ssh.SftpClient.CreateDirectoryAsync*> succeeds if the directory already exists. If you want the operation to fail if the directory already exists, you can call <xref:Tmds.Ssh.SftpClient.CreateNewDirectoryAsync*>.

<xref:Tmds.Ssh.SftpClient.DeleteDirectoryAsync*> removes a directory. Pass `recursive: true` to delete all contents:

```csharp
await sftpClient.DeleteDirectoryAsync("/remote/olddir", recursive: true);
```

<xref:Tmds.Ssh.SftpClient.DeleteDirectoryAsync*> also succeeds when the directory did not exist.

<xref:Tmds.Ssh.SftpClient.GetDirectoryEntriesAsync*> lists the contents of a directory. It takes a transform delegate that selects which data to extract from each entry:

```csharp
await foreach (var (path, length) in sftpClient.GetDirectoryEntriesAsync(
    "/remote/dir",
    (ref SftpFileEntry entry) => (entry.ToPath(), entry.Length)))
{
    Console.WriteLine($"{path} ({length} bytes)");
}
```

Pass <xref:Tmds.Ssh.EnumerationOptions> to recurse into subdirectories, follow links, or filter by file type:

```csharp
await foreach (string path in sftpClient.GetDirectoryEntriesAsync(
    "/remote/dir",
    (ref SftpFileEntry entry) => entry.ToPath(),
    new Tmds.Ssh.EnumerationOptions
    {
        RecurseSubdirectories = true,
        FileTypeFilter = UnixFileTypeFilter.RegularFile
    }))
{
    Console.WriteLine(path);
}
```

The `ShouldInclude` and `ShouldRecurse` predicates provide fine-grained control over which entries are returned and which subdirectories are traversed. `ExtendedAttributes` specifies which extended attributes to request from the server — pass `null` to request all.

### Working with files

To open a remote file, you can call the <xref:Tmds.Ssh.SftpClient.OpenFileAsync*> method. If the file does not exist, the method returns `null`. If you want to create the file when it doesn't exist yet, you can call <xref:Tmds.Ssh.SftpClient.OpenOrCreateFileAsync*> instead. Or, if you want to ensure a new file is created, you can call <xref:Tmds.Ssh.SftpClient.CreateNewFileAsync*> which will throw if the file already exists.

```csharp
using SftpFile file = await sftpClient.OpenOrCreateFileAsync("/remote/data.bin", FileAccess.ReadWrite);
```

The <xref:Tmds.Ssh.SftpFile> type that is returned derives from `Stream`. It provides additional methods to read and write at an offset:

```csharp
int bytesRead = await file.ReadAtAsync(buffer, offset: 0);
```

The behavior of the open can be controlled using <xref:Tmds.Ssh.FileOpenOptions>.

```csharp
using SftpFile file = await sftpClient.OpenOrCreateFileAsync("/remote/log.txt", FileAccess.Write,
    new FileOpenOptions { OpenMode = OpenMode.Append });
```

<xref:Tmds.Ssh.OpenMode>.Truncate clears the file on open. Set `CacheLength = true` to enable `Stream.Length` and `Stream.Seek`.

To delete a file, you can call <xref:Tmds.Ssh.SftpClient.DeleteFileAsync*>. The method also succeeds when the file did not exist.

```csharp
await sftpClient.DeleteFileAsync("/remote/file.txt");
```

### Working with symbolic links

<xref:Tmds.Ssh.SftpClient.CreateSymbolicLinkAsync*> creates a symbolic link:

```csharp
await sftpClient.CreateSymbolicLinkAsync("/remote/link", "/remote/target");
```

<xref:Tmds.Ssh.SftpClient.GetLinkTargetAsync*> reads the target of a symbolic link, and <xref:Tmds.Ssh.SftpClient.GetRealPathAsync*> resolves the canonical path:

```csharp
string target = await sftpClient.GetLinkTargetAsync("/remote/link");
string realPath = await sftpClient.GetRealPathAsync("/remote/link");
```

To delete a symbolic link, you can call <xref:Tmds.Ssh.SftpClient.DeleteFileAsync*>. The method also succeeds when the link did not exist.

```csharp
await sftpClient.DeleteFileAsync("/remote/link");
```

### Getting and changing attributes

<xref:Tmds.Ssh.SftpClient.GetAttributesAsync*> retrieves file metadata such as size and permissions:

```csharp
var attributes = await sftpClient.GetAttributesAsync("/remote/file.txt", followLinks: true);
if (attributes is not null)
{
    Console.WriteLine($"Length: {attributes.Length}");
    Console.WriteLine($"Permissions: {attributes.Permissions}");
}
```

The method returns `null` when the path does not exist. The returned <xref:Tmds.Ssh.FileEntryAttributes> includes `Length`, `FileType`, `Permissions`, `Uid`, `Gid`, `LastAccessTime`, `LastWriteTime`, and optionally `ExtendedAttributes`.

<xref:Tmds.Ssh.SftpClient.SetAttributesAsync*> modifies file metadata:

```csharp
await sftpClient.SetAttributesAsync("/remote/file.txt",
    permissions: UnixFilePermissions.UserRead | UnixFilePermissions.UserWrite);
```

<xref:Tmds.Ssh.SftpClient.SetAttributesAsync*> accepts optional parameters — only the values you pass are changed:

```csharp
await sftpClient.SetAttributesAsync("/remote/file.txt",
    times: (DateTime.UtcNow, DateTime.UtcNow),
    ids: (Uid: 1000, Gid: 1000));
```

### Monitor progress

SFTP operations that transfer data accept an optional <xref:Tmds.Ssh.SftpProgressHandler> for monitoring progress. Subclass it and override the methods you are interested in:

```csharp
class MyProgressHandler : SftpProgressHandler
{
    private long _startTime;
    private long _endTime;
    private long _totalBytesTransferred;

    protected override void Start(int maxConcurrentEntries)
        => _startTime = Stopwatch.GetTimestamp();

    protected override void DataTransferred(int index, long bytesTransferred, long offset)
        => Interlocked.Add(ref _totalBytesTransferred, bytesTransferred);

    protected override void Completed(Exception? exception)
        => _endTime = Stopwatch.GetTimestamp();

    public long TotalBytesTransferred
        => Interlocked.Read(ref _totalBytesTransferred);

    public TimeSpan Elapsed
        => Stopwatch.GetElapsedTime(_startTime, _endTime != 0 ? _endTime : Stopwatch.GetTimestamp());
}

var progress = new MyProgressHandler();
await sftpClient.UploadDirectoryEntriesAsync("/local/dir", "/remote/dir", progress: progress);
```

`Start` is always called synchronously before the async method returns its `ValueTask`. `Completed` is called at the end, including when the operation fails. Callbacks are invoked from background threads — use thread-safe operations like `Interlocked` to aggregate data, and defer UI updates to a separate thread. See <xref:Tmds.Ssh.SftpProgressHandler> for more information.

## .NET Tools

`ssh` and `ssh-cp` are .NET tools built using `Tmds.Ssh`. They provide an easy way to try `Tmds.Ssh` against an SSH server without writing code.

### ssh

`ssh` is an SSH client similar to OpenSSH `ssh`. With .NET 10+, it can be run directly:

```
dnx ssh user@example.com
```

On .NET 8+, install it as a .NET tool:

```
dotnet tool update -g ssh
dotnet ssh user@example.com
```

### ssh-cp

`ssh-cp` copies files to and from remote hosts, similar to OpenSSH `scp`:

```
dnx ssh-cp localfile.txt user@example.com:/remote/path/
dnx ssh-cp user@example.com:/remote/file.txt ./local/
```

On .NET 8+, install it as a .NET tool:

```
dotnet tool update -g ssh-cp
dotnet ssh-cp localfile.txt user@example.com:/remote/path/
```
