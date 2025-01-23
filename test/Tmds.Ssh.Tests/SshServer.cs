using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;
using SkipException = Xunit.SkipException;

namespace Tmds.Ssh.Tests;

public class SshServer : IDisposable
{
    private string ContainerImageName { get; }
    private const string ContainerBuildContext = "sshd_container";

    public static bool HasKerberos = HasExecutable("kinit");

    public string TestUser => "testuser";
    public string TestUserHome => $"/home/{TestUser}";
    public string TestUserPassword { get; }
    public NetworkCredential TestKerberosCredential => new NetworkCredential($"{TestUser}@REALM.TEST", "secret");
    public string TestUserIdentityFile => $"{ContainerBuildContext}/user_key_rsa";
    public string TestUserIdentityFileEcdsa256 => $"{ContainerBuildContext}/user_key_ecdsa_256";
    public string TestUserIdentityFileEcdsa384 => $"{ContainerBuildContext}/user_key_ecdsa_384";
    public string TestUserIdentityFileEcdsa521 => $"{ContainerBuildContext}/user_key_ecdsa_521";
    public string TestUserIdentityFileEd25519 => $"{ContainerBuildContext}/user_key_ed25519";
    public string TestSubsystem = "test_subsystem";
    public string ServerHost => _host;
    public int ServerPort => _port;
    public string KnownHostsFilePath => _knownHostsFile;
    public string KerberosConfigFilePath => _krbConfigFilePath;
    public string SshConfigFilePath => _sshConfigFilePath;
    public string Destination => $"{TestUser}@{ServerHost}:{ServerPort}";

    private string RsaKeySHA256FingerPrint => "sqggBLsad/k11YcLVgwFnq6Bs7WRYgD1u+WhBmVKMVM";
    private string Ed25519KeySHA256FingerPrint => "Y/HuDkfhwjCreznEiaX5tshGRPXZJvZ/Nj42hCsw9II";
    private string EcdsaKeyNistp256SHA256FingerPrint => "0983BezNRxXiCSK+ZY835dHQ3tSzx+i2oHd6vKKlOeE";
    private string EcdsaKeyNistp384SHA256FingerPrint => "O8vDVOPKzyWp38LkIyQwo+o9pZlV/10lCzCuWNuls+A";
    private string EcdsaKeyNistp521SHA256FingerPrint => "ki9Csen6gPmw24YqojLm12bNuftv+PgPlPIW/lwMk40";
    private string RsaKeyCertSHA256FingerPrint => "doUWiEWO/lCrZb9Z0xYUUmjodBViJ4+yg8nvmZJDxFg";
    private string Ed25519KeyCertSHA256FingerPrint => "UgJfSX2djCaEygDMBUWhZUOFWCqwnhFVMuRsPA+NPE4";
    private string EcdsaKeyCertNistp256SHA256FingerPrint => "e2utj7oy7iLfnMpc1FPd0oGo1ZnBZLVvXPQe/LIVKKI";
    private string EcdsaKeyCertNistp384SHA256FingerPrint => "QSIE3DZTPzgDrMeGLki+w9MKLPLKMAME4YVkEjChE9Y";
    private string EcdsaKeyCertNistp521SHA256FingerPrint => "gN4CGGEfs+6n7F9vIvl6xUEKcCzOu82+YtqwzjjirB8";
    public string CaSHA256FingerPrint => "0AheLeF8Ytfrk79e3sauimh2vFOK3Q03o0C3B9DmbWA";

    public string[] ServerKeySHA256FingerPrints => new string[]
    {
        RsaKeySHA256FingerPrint,
        Ed25519KeySHA256FingerPrint,
        EcdsaKeyNistp256SHA256FingerPrint,
        EcdsaKeyNistp384SHA256FingerPrint,
        EcdsaKeyNistp521SHA256FingerPrint,
    };

    public string[] ServerKeyCertSHA256FingerPrints => new string[]
    {
        RsaKeyCertSHA256FingerPrint,
        Ed25519KeyCertSHA256FingerPrint,
        EcdsaKeyCertNistp256SHA256FingerPrint,
        EcdsaKeyCertNistp384SHA256FingerPrint,
        EcdsaKeyCertNistp521SHA256FingerPrint,
    };

    private string RsaKeyPubFile = $"{ContainerBuildContext}/server_key_rsa.pub";
    private string Ed25519KeyPubFile = $"{ContainerBuildContext}/server_key_ecdsa.pub";
    private string EcdsaKeyNistp256PubFile = $"{ContainerBuildContext}/server_key_ecdsa_nistp384.pub";
    private string EcdsaKeyNistp384PubFile = $"{ContainerBuildContext}/server_key_ecdsa_nistp521.pub";
    private string EcdsaKeyNistp521PubFile = $"{ContainerBuildContext}/server_key_ed25519.pub";
    public string CAPubFile = $"{ContainerBuildContext}/ca.pub";

    private string[] KeyPubFiles => new string[]
    {
        RsaKeyPubFile,
        Ed25519KeyPubFile,
        EcdsaKeyNistp256PubFile,
        EcdsaKeyNistp384PubFile,
        EcdsaKeyNistp521PubFile,
    };

    private readonly string _containerId;
    private readonly string _host;
    private readonly int _port;
    private readonly string _knownHostsFile;
    private readonly string _krbConfigFilePath;
    private readonly string _sshConfigFilePath;
    private readonly string? _sshdConfigFilePath;
    private readonly IMessageSink _messageSink;
    private bool _useDockerInstead;

    public SshServer(IMessageSink messageSink) :
        this(null, messageSink)
    { }

    private void WriteMessage(string message)
    {
        _messageSink.OnMessage(new DiagnosticMessage(message));
    }

    protected SshServer(string? sshdConfig, IMessageSink messageSink, string userPassword = "secret")
    {
        TestUserPassword = userPassword;
        ContainerImageName = $"test_{GetType().Name.ToLowerInvariant()}:latest";

        _messageSink = messageSink;
        WriteMessage("Starting SSH server for tests.");

        _useDockerInstead = !HasContainerEngine("podman") &&
                            HasContainerEngine("docker");

        try
        {
            Run("podman", "build", $"--build-arg=PASSWORD={TestUserPassword}", "-t", ContainerImageName, ContainerBuildContext);
            IPAddress interfaceAddress = IPAddress.Loopback;
            _host = interfaceAddress.ToString();
            _port = PickFreePort(interfaceAddress);
            int kdcPort = PickFreePort(interfaceAddress);
            List<string> runArgs =
            [
                "-d",
                "-p", $"{_host}:{_port}:22",
                "-p", $"{_host}:{kdcPort}:88/tcp", "-p", $"{_host}:{kdcPort}:88/udp",
                "-h", "localhost"
            ];
            if (sshdConfig is not null)
            {
                _sshdConfigFilePath = Path.GetTempFileName();
                File.WriteAllText(_sshdConfigFilePath, sshdConfig);
                runArgs.AddRange(
                    [ "-v", $"{_sshdConfigFilePath}:/etc/ssh/sshd_config.d/10-custom.conf:z" ]
                );
            }
            _containerId = LastWord(Run("podman", ["run", ..runArgs, ContainerImageName]));
            do
            {
                string[] log = Run("podman", "logs", _containerId);
                if (log.Any(s => s.Contains("Server listening on :: port 22.")))
                {
                    break;
                }

                // Sleep 100ms.
                Thread.Sleep(100);

                // Check if the container is still running.
                string[] containers = Run("podman", "ps", "-q", "-f", $"id={_containerId}");
                if (containers.Length == 0)
                {
                    log = Run("podman", "logs", _containerId);
                    throw new InvalidOperationException("Failed to start ssh server" + Environment.NewLine
                                                            + string.Join(Environment.NewLine, log));
                }
            } while (true);

            _knownHostsFile = WriteKnownHostsFile(_host, _port);
            _krbConfigFilePath = WriteKerberosConfigFile(kdcPort);
            _sshConfigFilePath = WriteSshConfigFile(_knownHostsFile, TestUserIdentityFile);

            if (!OperatingSystem.IsWindows())
            {
                Run("chmod", "600", TestUserIdentityFile);
            }

            if (sshdConfig is null)
            {
                VerifyServerWorks();
            }

            WriteMessage("SSH server is running.");
        }
        catch
        {
            Dispose();

            throw;
        }

        static int PickFreePort(IPAddress interfaceAddress)
        {
            using var s = new Socket(interfaceAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            s.Bind(new IPEndPoint(interfaceAddress, 0));
            return (s.LocalEndPoint as IPEndPoint)!.Port;
        }

        string WriteKnownHostsFile(string host, int port)
        {
            string hostPattern = $"[{host}]:{port}";
            IEnumerable<string> lines = KeyPubFiles.Select(file => $"{hostPattern} {File.ReadAllText(file).Trim()}");
            string filename = Path.GetTempFileName();
            File.WriteAllLines(filename, lines);
            return filename;
        }

        string WriteSshConfigFile(string knownHostsFilePath, string identityFilePath)
        {
            string contents =
            $"""
            UserKnownHostsFile "{knownHostsFilePath}"
            IdentityFile "{identityFilePath}"
            """;
            string filename = Path.GetTempFileName();
            File.WriteAllText(filename, contents);
            return filename;
        }

        string WriteKerberosConfigFile(int kdcPort)
        {
            string configTemplate = File.ReadAllText(Path.Combine(ContainerBuildContext, "krb5.conf"));
            string configValue = configTemplate.Replace("localhost", $"localhost:{kdcPort}");
            string filename = Path.GetTempFileName();
            File.WriteAllText(filename, configValue);
            return filename;
        }

        static bool HasContainerEngine(string name)
        {
            try
            {
                var psi = new ProcessStartInfo()
                {
                    FileName = name,
                    ArgumentList = { "version" },
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true,
                };
                using var process = Process.Start(psi)!;
                process.WaitForExit();
                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }
    }

    private static bool HasExecutable(string executable)
    {
        try
        {
            // command is POSIX but is a shell-ism not a binary itself
            var psi = new ProcessStartInfo()
            {
                FileName = "sh",
                ArgumentList = { "-c", $"command -v {executable}" },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
            };
            using var process = Process.Start(psi)!;
            process.WaitForExit();
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static string LastWord(IEnumerable<string> lines)
        => lines.Last().Split(' ').Last();

    public void Dispose()
    {
        WriteMessage("Stopping SSH server.");
        try
        {
            if (_knownHostsFile != null)
            {
                File.Delete(_knownHostsFile);
            }
            if (_krbConfigFilePath != null)
            {
                File.Delete(_krbConfigFilePath);
            }
            if (_sshConfigFilePath != null)
            {
                File.Delete(_sshConfigFilePath);
            }
            if (_sshdConfigFilePath != null)
            {
                File.Delete(_sshdConfigFilePath);
            }
            if (_containerId != null)
            {
                Run("podman", "rm", "-f", _containerId);
            }
            // Don't remove the image to make the next test run faster.
            // Run("podman", "rmi", "-f", ContainerImageName);
        }
        catch
        { }
    }

    private void PrintServerLogs()
    {
        WriteMessage("SSH Server logs:");
        string[] log = Run("podman", "logs", _containerId);
        foreach (var line in log)
        {
            WriteMessage(line);
        }
    }

    private string[] Run(string filename, params string[] arguments)
        => Run(filename, arguments as IEnumerable<string>);

    private string[] Run(string filename, IEnumerable<string> arguments)
    {
        if (filename == "podman" && _useDockerInstead)
        {
            filename = "docker";
        }

        WriteMessage($"  exec: {filename} {string.Join(' ', arguments)}");
        var psi = new ProcessStartInfo()
        {
            FileName = filename,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        foreach (var arg in arguments)
        {
            psi.ArgumentList.Add(arg);
        }
        using var process = Process.Start(psi)!;
        var lines = new List<string>();
        DataReceivedEventHandler handler = (o, e) =>
        {
            if (e.Data == null)
            {
                return;
            }
            lock (lines)
            {
                // System.WriteMessage(e.Data);
                lines.Add(e.Data);
            }
        };
        process.OutputDataReceived += handler;
        process.ErrorDataReceived += handler;
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, string.Join(Environment.NewLine, lines));
        return lines.ToArray();
    }

    private void VerifyServerWorks()
    {
        try
        {
            const string HelloWorld = "Hello world!";
            string[] output = Run("ssh",
                                    "-i", TestUserIdentityFile,
                                    "-o", "BatchMode=yes",
                                    "-o", $"UserKnownHostsFile={KnownHostsFilePath}",
                                    "-p", ServerPort.ToString(),
                                    $"{TestUser}@{ServerHost}",
                                    $"echo '{HelloWorld}'"
            );
            Assert.NotEmpty(output);
            Assert.Contains(HelloWorld, output);
        }
        catch (Exception ex)
        {
            WriteMessage($"Verifying server works failed with: {ex}");
            PrintServerLogs();

            throw;
        }
    }

    public async Task<SshClient> CreateClientAsync(SshConfigSettings configSettings, CancellationToken cancellationToken = default, bool connect = true)
    {
        var client = new SshClient(Destination, configSettings);

        if (connect)
        {
            await client.ConnectAsync(cancellationToken);
        }

        return client;
    }

    public Task<SshClient> CreateClientAsync(Action<SshClientSettings>? configure = null, CancellationToken cancellationToken = default, bool connect = true)
    {
        var settings = CreateSshClientSettings(configure);

        return CreateClientAsync(settings, cancellationToken, connect);
    }

    public async Task<SshClient> CreateClientAsync(SshClientSettings settings, CancellationToken cancellationToken = default, bool connect = true)
    {
        var client = new SshClient(settings);

        if (connect)
        {
            await client.ConnectAsync(cancellationToken);
        }

        return client;
    }

    public async Task<SftpClient> CreateSftpClientAsync(Tmds.Ssh.Tests.SftpExtension enabledExtensions, Action<SshClientSettings>? configureSsh = null, CancellationToken cancellationToken = default)
    {
        var settings = CreateSshClientSettings(configureSsh);

        SftpClientOptions? options = new()
        {
            DisabledExtensions = (Tmds.Ssh.SftpExtension)~enabledExtensions
        };

        var client = new SftpClient(settings, options: options);

        await client.ConnectAsync(cancellationToken);

        if (client.EnabledExtensions != (Tmds.Ssh.SftpExtension)enabledExtensions)
        {
            throw new SkipException($"The test server does not support the required {((Tmds.Ssh.SftpExtension)enabledExtensions) & ~client.EnabledExtensions} extensions.");
        }

        return client;
    }

    public async Task<SftpClient> CreateSftpClientAsync(Action<SshClientSettings>? configureSsh = null, Action<SftpClientOptions>? configureSftp = null, CancellationToken cancellationToken = default, bool connect = true)
    {
        var settings = CreateSshClientSettings(configureSsh);

        SftpClientOptions? sftpClientOptions = null;
        if (configureSftp is not null)
        {
            sftpClientOptions = new();
            configureSftp.Invoke(sftpClientOptions);
        }

        var client = new SftpClient(settings, options: sftpClientOptions);

        if (connect)
        {
            await client.ConnectAsync(cancellationToken);
        }

        return client;
    }

    public SshClientSettings CreateSshClientSettings(Action<SshClientSettings>? configure = null)
    {
        var settings = new SshClientSettings(Destination)
        {
            UserKnownHostsFilePaths = [ KnownHostsFilePath ],
            Credentials = [ new PrivateKeyCredential(TestUserIdentityFile) ],
        };
        configure?.Invoke(settings);
        return settings;
    }
}

[CollectionDefinition(nameof(SshServerCollection))]
public class SshServerCollection : ICollectionFixture<SshServer>
{
    // This class has no code, and is never created. Its purpose is simply
    // to be the place to apply [CollectionDefinition] and all the
    // ICollectionFixture<> interfaces.
}

public class MultiMethodAuthSshServer : SshServer
{
    public const string Config =
        """
        AuthenticationMethods publickey,password
        """;

    public Credential FirstCredential { get; }    
    public Credential SecondCredential { get; }

    public MultiMethodAuthSshServer(IMessageSink messageSink) :
        base(Config, messageSink)
    {
        FirstCredential = new PrivateKeyCredential(TestUserIdentityFile);
        SecondCredential = new PasswordCredential(TestUserPassword);
    }
}

[CollectionDefinition(nameof(MultiMethodAuthSshServerCollection))]
public class MultiMethodAuthSshServerCollection : ICollectionFixture<MultiMethodAuthSshServer>
{
    // This class has no code, and is never created. Its purpose is simply
    // to be the place to apply [CollectionDefinition] and all the
    // ICollectionFixture<> interfaces.
}

public class NoneAuthSshServer : SshServer
{
    public const string Config =
        """
        PasswordAuthentication yes
        PermitEmptyPasswords yes
        AuthenticationMethods none
        """;

    public NoneAuthSshServer(IMessageSink messageSink) :
        base(Config, messageSink,
            // For OpenSSH to allow 'none', the user needs an empty password.
            userPassword: "")
    { }
}

[CollectionDefinition(nameof(NoneAuthSshServerCollection))]
public class NoneAuthSshServerCollection : ICollectionFixture<NoneAuthSshServer>
{
    // This class has no code, and is never created. Its purpose is simply
    // to be the place to apply [CollectionDefinition] and all the
    // ICollectionFixture<> interfaces.
}
