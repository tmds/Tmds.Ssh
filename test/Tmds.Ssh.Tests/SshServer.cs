using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Xunit;

namespace Tmds.Ssh.Tests
{
    public class SshServer : IDisposable
    {
        private const string ContainerBuildContext = "sshd_container";

        public string TestUser => "testuser";
        public string TestUserPassword => "secret";
        public string TestUserIdentityFile => $"{ContainerBuildContext}/user_key_rsa";
        public string ServerHost => _host;
        public int ServerPort => _port;
        public string KnownHostsFile => _knownHostsFile;

        private readonly string _imageId;
        private readonly string _containerId;
        private readonly string _host;
        private readonly int _port;
        private readonly string _knownHostsFile;

        public SshServer()
        {
            try
            {
                _imageId = Run("podman", "build", ContainerBuildContext).Last();
                IPAddress interfaceAddress = IPAddress.Loopback;
                _host = interfaceAddress.ToString();
                _port = PickFreePort(interfaceAddress);
                _containerId = Run("podman", "run", "--rm", "-d", "-p", $"{_host}:{_port}:22", _imageId).Last();
                _knownHostsFile = WriteKnownHostsFile(_host, _port);
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

                Run("chmod", "600", TestUserIdentityFile);

                VerifyServerWorks();
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

            static string WriteKnownHostsFile(string host, int port)
            {
                List<string> knownHostLines = new();
                foreach (var keyFile in new[]
                            { $"{ContainerBuildContext}/server_key_rsa.pub",
                              $"{ContainerBuildContext}/server_key_ecdsa.pub",
                              $"{ContainerBuildContext}/server_key_ed25519.pub" })
                {
                    var lines = File.ReadLines(keyFile);
                    foreach (var line in lines)
                    {
                        string[] split = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                        if (split.Length >= 2)
                        {
                            knownHostLines.Add($"[{host}]:{port} {split[0]} {split[1]}");
                        }
                    }
                }
                string filename = Path.GetTempFileName();
                File.WriteAllLines(filename, knownHostLines);
                return filename;
            }
        }

        public void Dispose()
        {
            if (_knownHostsFile != null)
            {
                File.Delete(_knownHostsFile);
            }
            if (_imageId != null)
            {
                Run("podman", "rmi", "-f", _imageId);
            }
        }

        private string[] Run(string filename, params string[] arguments)
        {
            // Console.WriteLine($"Running {filename} {string.Join(' ', arguments)}");
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
            do
            {
                string? line = process.StandardOutput.ReadLine();
                if (line == null)
                {
                    break;
                }
                lines.Add(line);
            } while (true);
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, process.StandardError.ReadToEnd());
            return lines.ToArray();
        }

        private void VerifyServerWorks()
        {
            const string HelloWorld = "Hello world!";
            string[] output = Run("ssh",
                                    "-i", TestUserIdentityFile,
                                    "-o", "BatchMode=yes",
                                    "-o", $"UserKnownHostsFile={KnownHostsFile}",
                                    "-p", ServerPort.ToString(),
                                    $"{TestUser}@{ServerHost}",
                                    $"echo '{HelloWorld}'"
            );
            Assert.NotEmpty(output);
            Assert.Equal(HelloWorld, output[0]);
        }
    }

    [CollectionDefinition(nameof(SshServerCollection))]
    public class SshServerCollection : ICollectionFixture<SshServer>
    {
        // This class has no code, and is never created. Its purpose is simply
        // to be the place to apply [CollectionDefinition] and all the
        // ICollectionFixture<> interfaces.
    }
}