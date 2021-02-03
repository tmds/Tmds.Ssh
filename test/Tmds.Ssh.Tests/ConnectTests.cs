using System;
using Xunit;

using System.Threading;
using System.Threading.Tasks;

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
        public async Task NotAKnownHost()
        {
            await Assert.ThrowsAsync<SshSessionException>(() =>
                _sshServer.CreateClientAsync(
                    settings => settings.KnownHostFile = "/"
                ));
        }

        [Fact]
        public async Task KeyVerificationConnectionInfo()
        {
            await _sshServer.CreateClientAsync(
                settings =>
                {
                    settings.KnownHostFile = "/";
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
        public async Task NoCredentials()
        {
            await Assert.ThrowsAsync<SshSessionException>(() =>
                _sshServer.CreateClientAsync(
                    settings => settings.Credentials.Clear()
                ));
        }
    }
}
