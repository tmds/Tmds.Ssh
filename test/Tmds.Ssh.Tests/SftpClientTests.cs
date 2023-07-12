using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Tmds.Ssh.Tests
{
    [Collection(nameof(SshServerCollection))]
    public class SftpClientTests
    {
        private readonly SshServer _sshServer;

        public SftpClientTests(SshServer sshServer)
        {
            _sshServer = sshServer;
        }

        [Fact]
        public async Task OpenClient()
        {
            using var client = await _sshServer.CreateClientAsync();
            using var sftpClient = await client.OpenSftpClientAsync();
        }

        [InlineData(10)]
        [InlineData(10 * 1024)] // 10 kiB
        [InlineData(10 * 1024 * 1024)] // 10 MiB
        [Theory]
        public async Task ReadWriteFile(int fileSize)
        {
            using var client = await _sshServer.CreateClientAsync();
            using var sftpClient = await client.OpenSftpClientAsync();
            string filename = $"/tmp/{Path.GetRandomFileName()}";

            byte[] writeBuffer = new byte[fileSize];

            using var writeFile = await sftpClient.OpenFileAsync(filename, OpenFlags.CreateNew | OpenFlags.Write);
            Random.Shared.NextBytes(writeBuffer);
            await writeFile.WriteAsync(writeBuffer.AsMemory(0, fileSize));
            Assert.Equal(fileSize, writeFile.Position);
            await writeFile.CloseAsync();

            byte[] receiveBuffer = new byte[fileSize + 10];

            using var readFile = await sftpClient.OpenFileAsync(filename, OpenFlags.Open | OpenFlags.Read);
            int bytesReceived = 0;
            int bytesRead = 0;
            while (bytesReceived < fileSize)
            {
                bytesRead = await readFile.ReadAsync(receiveBuffer);
                Assert.Equal(writeBuffer.AsSpan(bytesReceived, bytesRead).ToArray(), receiveBuffer.AsSpan(0, bytesRead).ToArray());
                bytesReceived += bytesRead;
            }
            bytesRead = await readFile.ReadAsync(receiveBuffer);
            Assert.Equal(0, bytesRead);
            Assert.Equal(fileSize, bytesReceived);
            Assert.Equal(fileSize, readFile.Position);
            await readFile.CloseAsync();
        }
    }
}
