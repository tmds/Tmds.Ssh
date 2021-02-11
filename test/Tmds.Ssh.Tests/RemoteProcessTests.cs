using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Tmds.Ssh.Tests
{
    [Collection(nameof(SshServerCollection))]
    public class RemoteProcess
    {
        private readonly SshServer _sshServer;

        public RemoteProcess(SshServer sshServer)
        {
            _sshServer = sshServer;
        }

        [Theory]
        [InlineData(ProcessReadType.StandardOutput)]
        [InlineData(ProcessReadType.StandardError)]
        public async Task HelloWorld(ProcessReadType readType)
        {
            using var client = await _sshServer.CreateClientAsync();
            byte[] helloWorldBytes = Encoding.UTF8.GetBytes("hello world");
            string command = "echo -n 'hello world'";
            if (readType == ProcessReadType.StandardError)
            {
                command += " >&2";
            }
            using var process = await client.ExecuteAsync(command);

            byte[] buffer = new byte[512];
            (ProcessReadType type, int bytesRead) = await process.ReadAsync(buffer, buffer);
            Assert.Equal(readType, type);
            Assert.Equal(helloWorldBytes, buffer.AsSpan(0, bytesRead).ToArray());

            (type, bytesRead) = await process.ReadAsync(buffer, buffer);
            Assert.Equal(ProcessReadType.ProcessExit, type);
            Assert.Equal(0, bytesRead);

            Assert.Equal(0, process.ExitCode);
        }

        public enum WriteApi
        {
            WriteAsync,
            StandardInputStream,
            StandardInputWriter,
        }

        [Theory]
        [InlineData(WriteApi.WriteAsync)]
        [InlineData(WriteApi.StandardInputStream)]
        [InlineData(WriteApi.StandardInputWriter)]
        public async Task WriteAndRead(WriteApi writeApi)
        {
            using var client = await _sshServer.CreateClientAsync();
            string helloWorld = "hello world";
            byte[] helloWorldBytes = Encoding.UTF8.GetBytes(helloWorld);
            using var process = await client.ExecuteAsync("cat");

            switch (writeApi)
            {
                case WriteApi.WriteAsync:
                    await process.WriteAsync(helloWorldBytes);
                    break;
                case WriteApi.StandardInputStream:
                    await process.StandardInputStream.WriteAsync(helloWorldBytes);
                    break;
                case WriteApi.StandardInputWriter:
                    await process.StandardInputWriter.WriteAsync(helloWorld);
                    break;
            }

            byte[] buffer = new byte[512];
            (ProcessReadType type, int bytesRead) = await process.ReadAsync(buffer, buffer);
            Assert.Equal(ProcessReadType.StandardOutput, type);
            Assert.Equal(helloWorldBytes, buffer.AsSpan(0, bytesRead).ToArray());
        }

        [Fact]
        public async Task LargeWriteAndRead()
        {
            using var client = await _sshServer.CreateClientAsync();
            byte[] writeBuffer = new byte[10_000_000];
            var random = new Random();
            random.NextBytes(writeBuffer);
            {
                using var process = await client.ExecuteAsync($"cat >/tmp/{nameof(LargeWriteAndRead)}");

                await process.WriteAsync(writeBuffer);
            }

            MemoryStream ms = new MemoryStream();
            {
                using var process = await client.ExecuteAsync($"cat /tmp/{nameof(LargeWriteAndRead)}");
                byte[] readBuffer = new byte[10_000_000];
                while (true)
                {
                    (ProcessReadType type, int bytesRead) = await process.ReadAsync(readBuffer, readBuffer);
                    if (type == ProcessReadType.ProcessExit)
                    {
                        break;
                    }
                    Assert.Equal(ProcessReadType.StandardOutput, type);
                    Assert.NotEqual(0, bytesRead);
                    ms.Write(readBuffer.AsSpan(0, bytesRead));
                }
            }
            Assert.Equal(writeBuffer, ms.ToArray());
        }

        [Fact]
        public async Task StandardInputStreamWrapsSshExceptionAsIOException()
        {
            using var client = await _sshServer.CreateClientAsync();
            using var process = await client.ExecuteAsync("exit 0");

            (ProcessReadType type, int bytesRead) = await process.ReadAsync(null, null);
            Assert.Equal(ProcessReadType.ProcessExit, type);
            Assert.Equal(0, bytesRead);

            var ioException = await Assert.ThrowsAsync<IOException>(() =>
                process.StandardInputStream.WriteAsync(new byte[1]).AsTask());

            Assert.IsType<SshOperationException>(ioException.InnerException);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1000)]
        public async Task CancelRead(int msTimeout)
        {
            using var client = await _sshServer.CreateClientAsync();
            using var process = await client.ExecuteAsync("sleep 600");

            CancellationTokenSource cts = new();
            cts.CancelAfter(msTimeout);
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                process.ReadAsync(null, null, cts.Token).AsTask());
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)] // TODO: this is a bit racy.
        public async Task CancelExecute(bool preNotPost)
        {
            using var client = await _sshServer.CreateClientAsync();
            CancellationTokenSource cts = new();
            if (preNotPost)
            {
                cts.Cancel();
            }
            var task = Assert.ThrowsAsync<OperationCanceledException>(() =>
                client.ExecuteAsync("sleep 600", cts.Token));
            if (!preNotPost)
            {
                cts.Cancel();
            }
            await task;
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)] // TODO: this is a bit racy.
        public async Task CancelWrite(bool preNotPost)
        {
            using var client = await _sshServer.CreateClientAsync();
            byte[] writeBuffer = new byte[10_000_000];
            using var process = await client.ExecuteAsync($"cat >/dev/null");
            CancellationTokenSource cts = new();
            if (preNotPost)
            {
                cts.Cancel();
            }
            var task = Assert.ThrowsAsync<OperationCanceledException>(() =>
                process.WriteAsync(writeBuffer, cts.Token).AsTask());
            if (!preNotPost)
            {
                cts.Cancel();
            }
            await task;
        }

        [Theory]
        [InlineData(0)]
        [InlineData(42)]
        public async Task ExitCodeAndHasExited(int exitCode)
        {
            using var client = await _sshServer.CreateClientAsync();
            using var process = await client.ExecuteAsync($"exit {exitCode}");

            (ProcessReadType type, int bytesRead) = await process.ReadAsync(null, null);
            Assert.Equal(ProcessReadType.ProcessExit, type);
            Assert.Equal(0, bytesRead);

            Assert.Equal(exitCode, process.ExitCode);
            Assert.True(process.HasExited);
        }

        [Fact]
        public async Task CancelAfterCancel()
        {
            using var client = await _sshServer.CreateClientAsync();
            using var process = await client.ExecuteAsync("sleep 600");

            CancellationToken ct = new CancellationToken(true);
            // Pass canceled token.
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                process.ReadAsync(null, null, ct).AsTask());
            // Pass canceled token again.
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                process.ReadAsync(null, null, ct).AsTask());
            // Call without token.
            await Assert.ThrowsAsync<SshOperationException>(() =>
                process.ReadAsync(null, null).AsTask());
        }
    }
}
