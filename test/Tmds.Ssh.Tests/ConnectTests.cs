using System;
using Xunit;

using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Tmds.Ssh.Tests
{
    [Collection(nameof(SshServerCollection))]
    public class ConnectTests
    {
        private readonly SshServer _sshServer;

        public ConnectTests(SshServer sshServer)
        {
            _sshServer = sshServer;
        }

        [Fact]
        public async Task ConnectSuccess()
        {
            using var _ = await _sshServer.CreateClientAsync();
        }

        [Fact]
        public async Task UnknownHostConnectThrows()
        {
            await Assert.ThrowsAsync<SshSessionException>(() =>
                _sshServer.CreateClientAsync(settings => 
                    settings.KnownHostsFilePath = "/"
                ));
        }

        [Fact]
        public async Task KeyVerificationHasConnectionInfo()
        {
            using var _ = await _sshServer.CreateClientAsync(settings =>
                {
                    settings.KnownHostsFilePath = "/";
                    settings.KeyVerification =
                    (KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                    {
                        Assert.Equal(KeyVerificationResult.Unknown, knownHostResult);
                        Assert.Equal(_sshServer.ServerHost, connectionInfo.Host);
                        Assert.Equal(_sshServer.ServerPort, connectionInfo.Port);
                        Assert.NotEqual(0, connectionInfo.ServerKey.SHA256Hash.Length); // TODO: check hash.
                        return new ValueTask<KeyVerificationResult>(KeyVerificationResult.Trusted);
                    };
                }
            );
        }

        [Fact]
        public async Task NoKnownHosts()
        {
            using var _ = await _sshServer.CreateClientAsync(settings =>
                {
                    settings.KnownHostsFilePath = null;
                    settings.CheckGlobalKnownHostsFile = false;
                    settings.KeyVerification =
                    (KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                    {
                        return new ValueTask<KeyVerificationResult>(KeyVerificationResult.Trusted);
                    };
                }
            );
        }

        [Theory]
        [InlineData(KeyVerificationResult.Revoked)]
        [InlineData(KeyVerificationResult.Error)]
        [InlineData(KeyVerificationResult.Changed)]
        [InlineData(KeyVerificationResult.Unknown)]
        public async Task UntrustedKeyVerificationThrows(KeyVerificationResult result)
        {
            await Assert.ThrowsAsync<SshSessionException>(() =>
                _sshServer.CreateClientAsync(settings =>
                {
                    settings.KnownHostsFilePath = "/";
                    settings.KeyVerification =
                    (KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                    {
                        return new ValueTask<KeyVerificationResult>(result);
                    };
                }
            ));
        }

        [Fact]
        public async Task AddKnownHost()
        {
            string knownHostsFileName = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            try
            {
                Assert.False(File.Exists(knownHostsFileName));

                bool keyVerified = false;
                SshClient client = await _sshServer.CreateClientAsync(settings =>
                    {
                        settings.KnownHostsFilePath = knownHostsFileName;
                        settings.KeyVerification =
                        (KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                        {
                            keyVerified = true;
                            Assert.Equal(KeyVerificationResult.Unknown, knownHostResult);
                            return ValueTask.FromResult(KeyVerificationResult.AddKnownHost);
                        };
                    });
                client.Dispose();
                Assert.True(keyVerified);
                Assert.True(File.Exists(knownHostsFileName));

                client = await _sshServer.CreateClientAsync(settings =>
                {
                    settings.KnownHostsFilePath = knownHostsFileName;
                    settings.KeyVerification =
                    (KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                    {
                        Assert.True(false);
                        return ValueTask.FromResult(knownHostResult);
                    };
                });
                client.Dispose();
            }
            finally
            {
                try
                {
                    File.Delete(knownHostsFileName);
                }
                catch
                { }
            }
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public async Task AddKnownHostDoesNotErrorWithEmptyPath(string? path)
        {
            using SshClient client = await _sshServer.CreateClientAsync(settings =>
            {
                settings.KnownHostsFilePath = path;
                settings.KeyVerification =
                (KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                {
                    return ValueTask.FromResult(KeyVerificationResult.AddKnownHost);
                };
            });
        }

        [Fact]
        public async Task NoCredentialsConnectThrows()
        {
            await Assert.ThrowsAsync<SshSessionException>(() =>
                _sshServer.CreateClientAsync(settings =>
                    settings.Credentials.Clear()
                ));
        }

        [InlineData(true)]
        [InlineData(false)]
        [Theory]
        public async Task PasswordCredential(bool correctPassword)
        {
            var settings = new SshClientSettings(_sshServer.Destination)
            {
                KnownHostsFilePath = _sshServer.KnownHostsFilePath,
                Credentials = { new PasswordCredential(correctPassword ? _sshServer.TestUserPassword : "invalid" ) },
            };
            using var client = new SshClient(settings);

            if (correctPassword)
            {
                await client.ConnectAsync();
            }
            else
            {
                await Assert.ThrowsAsync<SshSessionException>(() => client.ConnectAsync());
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1000)]
        public async Task Timeout(int msTimeout)
        {
            IPAddress address = IPAddress.Loopback;
            using var s = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            s.Bind(new IPEndPoint(address, 0));
            s.Listen();
            int port = (s.LocalEndPoint as IPEndPoint)!.Port;

            using var client = new SshClient(
                new SshClientSettings($"user@{address}:{port}")
                {
                    ConnectTimeout = TimeSpan.FromMilliseconds(msTimeout)
                });
            SshSessionException exception = await Assert.ThrowsAsync<SshSessionException>(() => client.ConnectAsync());
            Assert.IsType<TimeoutException>(exception.InnerException);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1000)]
        public async Task CancelConnect(int msTimeout)
        {
            IPAddress address = IPAddress.Loopback;
            using var s = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            s.Bind(new IPEndPoint(address, 0));
            s.Listen();
            int port = (s.LocalEndPoint as IPEndPoint)!.Port;

            using var client = new SshClient($"user@{address}:{port}");

            CancellationTokenSource cts = new();
            cts.CancelAfter(msTimeout);
            await Assert.ThrowsAsync<OperationCanceledException>(() => client.ConnectAsync(cts.Token));
        }

        [Fact]
        public async Task CancelVerification()
        {
            CancellationTokenSource cts = new();
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                _sshServer.CreateClientAsync(settings =>
                {
                    settings.KnownHostsFilePath = "/";
                    settings.KeyVerification =
                    (KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                    {
                        cts.Cancel();
                        Assert.True(cancellationToken.IsCancellationRequested);
                        cancellationToken.ThrowIfCancellationRequested();
                        return new ValueTask<KeyVerificationResult>(KeyVerificationResult.Unknown);
                    };
                }, cts.Token
            ));
        }

        [Fact]
        public async Task CancelAuthentication()
        {
            CancellationTokenSource cts = new();
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                _sshServer.CreateClientAsync(settings =>
                {
                    settings.KnownHostsFilePath = "/";
                    settings.KeyVerification =
                    (KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                    {
                        cts.Cancel();
                        return new ValueTask<KeyVerificationResult>(KeyVerificationResult.Trusted);
                    };
                }, cts.Token
            ));
        }

        [Fact]
        public async Task VerificationExceptionWrapped()
        {
            var exceptionThrown = new Exception("Any exception");

            CancellationTokenSource cts = new();
            var ex = await Assert.ThrowsAsync<SshSessionException>(() =>
                _sshServer.CreateClientAsync(settings =>
                {
                    settings.KnownHostsFilePath = "/";
                    settings.KeyVerification =
                    (KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
                    {
                        throw exceptionThrown;
                    };
                }, cts.Token
            ));

            Assert.Equal(exceptionThrown, ex.InnerException);
        }
    }
}
