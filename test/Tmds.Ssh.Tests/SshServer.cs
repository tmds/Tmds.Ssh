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
        private bool _useDockerInstead;

        public SshServer()
        {
            _useDockerInstead = !HasContainerEngine("podman") &&
                                HasContainerEngine("docker");

            try
            {
                _imageId = LastWord(Run("podman", "build", ContainerBuildContext));
                IPAddress interfaceAddress = IPAddress.Loopback;
                _host = interfaceAddress.ToString();
                _port = PickFreePort(interfaceAddress);
                _containerId = LastWord(Run("podman", "run", "-d", "-p", $"{_host}:{_port}:22", _imageId));
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
                        log = RunCore("podman", returnStderr: _useDockerInstead, "logs", _containerId);
                        throw new InvalidOperationException("Failed to start ssh server" + Environment.NewLine
                                                                + string.Join(Environment.NewLine, log));
                    }
                } while (true);

                _knownHostsFile = WriteKnownHostsFile(_host, _port);

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

        private static string LastWord(string[] lines)
            => lines.Last().Split(' ').Last();

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
            =>  RunCore(filename, returnStderr: false, arguments);

        private string[] RunCore(string filename, bool returnStderr, params string[] arguments)
        {
            if (filename == "podman" && _useDockerInstead)
            {
                filename = "docker";
            }

            Console.WriteLine($"Running {filename} {string.Join(' ', arguments)}");
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
                string? line = returnStderr ? process.StandardError.ReadLine() :
                                              process.StandardOutput.ReadLine();
                if (line == null)
                {
                    break;
                }
                System.Console.WriteLine($"> {line}");
                lines.Add(line);
            } while (true);
            process.WaitForExit();
            Assert.True(process.ExitCode == 0,
                           returnStderr ? string.Join(Environment.NewLine, lines) :
                                          process.StandardError.ReadToEnd());
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