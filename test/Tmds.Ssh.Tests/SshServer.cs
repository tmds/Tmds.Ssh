using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Tmds.Ssh.Tests;

public class SshServer : IDisposable
{
    private const string ContainerImageName = "test_sshd:latest";
    private const string ContainerBuildContext = "sshd_container";

    public string TestUser => "testuser";
    public string TestUserHome => $"/home/{TestUser}";
    public string TestUserPassword => "secret";
    public string TestUserIdentityFile => $"{ContainerBuildContext}/user_key_rsa";
    public string TestSubsystem = "tmds_test";
    public string ServerHost => _host;
    public int ServerPort => _port;
    public string KnownHostsFilePath => _knownHostsFile;
    public string Destination => $"{TestUser}@{ServerHost}:{ServerPort}";

    public string RsaKeySHA256FingerPrint => "sqggBLsad/k11YcLVgwFnq6Bs7WRYgD1u+WhBmVKMVM";
    public string Ed25519KeySHA256FingerPrint => "Y/HuDkfhwjCreznEiaX5tshGRPXZJvZ/Nj42hCsw9II";
    public string EcdsaKeySHA256FingerPrint => "0983BezNRxXiCSK+ZY835dHQ3tSzx+i2oHd6vKKlOeE";

    private readonly string _containerId;
    private readonly string _host;
    private readonly int _port;
    private readonly string _knownHostsFile;
    private bool _useDockerInstead;

    public SshServer()
    {
        Console.WriteLine("Starting SSH server for tests.");

        _useDockerInstead = !HasContainerEngine("podman") &&
                            HasContainerEngine("docker");

        try
        {
            Run("podman", "build", "-t", ContainerImageName, ContainerBuildContext);
            IPAddress interfaceAddress = IPAddress.Loopback;
            _host = interfaceAddress.ToString();
            _port = PickFreePort(interfaceAddress);
            _containerId = LastWord(Run("podman", "run", "-d", "-p", $"{_host}:{_port}:22", ContainerImageName));
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

            if (!OperatingSystem.IsWindows())
            {
                Run("chmod", "600", TestUserIdentityFile);
            }

            VerifyServerWorks();

            Console.WriteLine("SSH server is running.");
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
            string[] lines = Run("ssh-keyscan", "-p", port.ToString(), host);
            string filename = Path.GetTempFileName();
            File.WriteAllLines(filename, lines);
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

    private static string LastWord(IEnumerable<string> lines)
        => lines.Last().Split(' ').Last();

    public void Dispose()
    {
        System.Console.WriteLine("Stopping SSH server.");
        try
        {
            if (_knownHostsFile != null)
            {
                File.Delete(_knownHostsFile);
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

    private string[] Run(string filename, params string[] arguments)
    {
        if (filename == "podman" && _useDockerInstead)
        {
            filename = "docker";
        }

        Console.WriteLine($"  exec: {filename} {string.Join(' ', arguments)}");
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
                // System.Console.WriteLine(e.Data);
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

    public async Task<SshClient> CreateClientAsync(Action<SshClientSettings>? configure = null, CancellationToken cancellationToken = default, bool connect = true)
    {
        var settings = CreateSshClientSettings(configure);

        var client = new SshClient(settings);

        if (connect)
        {
            await client.ConnectAsync(cancellationToken);
        }

        return client;
    }

    public async Task<SftpClient> CreateSftpClientAsync(Action<SshClientSettings>? configureSsh = null, CancellationToken cancellationToken = default, bool connect = true)
    {
        var settings = CreateSshClientSettings(configureSsh);

        var client = new SftpClient(settings);

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
            KnownHostsFilePath = KnownHostsFilePath,
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
