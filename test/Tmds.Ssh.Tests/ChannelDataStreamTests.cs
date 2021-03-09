using System;
using System.Threading.Tasks;
using System.Text;

using Xunit;

namespace Tmds.Ssh.Tests
{
    [Collection(nameof(SshServerCollection))]
    public class SshDataStreamTests
    {
        private readonly SshServer _sshServer;

        public SshDataStreamTests(SshServer sshServer)
        {
            _sshServer = sshServer;
        }

        [Fact]
        public async Task TcpConnection()
        {
            using var client = await _sshServer.CreateClientAsync();

            // start a an echo server using socat.
            const int socatPort = 1234;
            using var soCatProcess = await client.ExecuteAsync($"socat -v tcp-l:{socatPort},fork exec:'/bin/cat'");
            await Task.Delay(100); // wait a little for socat to start.

            using var connection = await client.OpenTcpConnectionAsync("localhost", socatPort);

            byte[] helloWorldBytes = Encoding.UTF8.GetBytes("hello world");
            await connection.WriteAsync(helloWorldBytes);

            byte[] receiveBuffer = new byte[128];
            int bytesRead = await connection.ReadAsync(receiveBuffer);

            Assert.Equal(helloWorldBytes.Length, bytesRead);
            Assert.Equal(helloWorldBytes, receiveBuffer.AsSpan(0, bytesRead).ToArray());
        }

        [Fact]
        public async Task TcpConnectionFail()
        {
            using var client = await _sshServer.CreateClientAsync();

            await Assert.ThrowsAsync<SshOperationException>(() => client.OpenTcpConnectionAsync("localhost", 2000));
        }
    }
}
