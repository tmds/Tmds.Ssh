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
    public class RemoteProcess
    {
        private readonly SshServer _sshServer;

        public RemoteProcess(SshServer sshServer)
        {
            _sshServer = sshServer;
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task HelloWorld(bool stderr)
        {
            using var client = await _sshServer.CreateClientAsync();
            byte[] helloWorldBytes = Encoding.UTF8.GetBytes("hello world");
            string command = "echo -n 'hello world'";
            if (stderr)
            {
                command += " >&2";
            }
            using var process = await client.ExecuteAsync(command);

            byte[] buffer = new byte[512];
            (bool isError, int bytesRead) = await process.ReadAsync(buffer, buffer);
            Assert.Equal(stderr, isError);
            Assert.Equal(helloWorldBytes, buffer.AsSpan(0, bytesRead).ToArray());

            (isError, bytesRead) = await process.ReadAsync(buffer, buffer);
            Assert.Equal(false, isError);
            Assert.Equal(0, bytesRead);

            Assert.Equal(0, process.ExitCode);
        }

        [Fact]
        public async Task ExitCodeThrowsInvalidOperationExceptionWhenProcessNotExited()
        {
            using var client = await _sshServer.CreateClientAsync();
            using var process = await client.ExecuteAsync("sleep 60");
            Assert.Throws<InvalidOperationException>(() => process.ExitCode);
        }

        [Fact]
        public async Task WaitForExit()
        {
            using var client = await _sshServer.CreateClientAsync();
            using var process = await client.ExecuteAsync("sleep 1");
            await process.WaitForExitAsync();
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
            (bool isError, int bytesRead) = await process.ReadAsync(buffer, buffer);
            Assert.Equal(false, isError);
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
                    (bool isError, int bytesRead) = await process.ReadAsync(readBuffer, readBuffer);
                    if (bytesRead == 0)
                    {
                        break;
                    }
                    Assert.Equal(false, isError);
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

            (bool isError, int bytesRead) = await process.ReadAsync(null, null);
            Assert.Equal(false, isError);
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
        public async Task ExitCode(int exitCode)
        {
            using var client = await _sshServer.CreateClientAsync();
            using var process = await client.ExecuteAsync($"exit {exitCode}");

            (bool isError, int bytesRead) = await process.ReadAsync(null, null);
            Assert.Equal(false, isError);
            Assert.Equal(0, bytesRead);

            Assert.Equal(exitCode, process.ExitCode);
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

        [Theory]
        [InlineData(true, true)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(false, false)]
        public async Task ReadToEndAsStringAsync(bool readStdout, bool readStderr)
        {
            using var client = await _sshServer.CreateClientAsync();
            using var process = await client.ExecuteAsync("bash");

            await process.WriteLineAsync("echo -n 'hello stdout1'");
            await process.WriteLineAsync("echo -n 'hello stderr1' >&2");
            await process.WriteLineAsync("sleep 1");
            await process.WriteLineAsync("echo -n 'hello stdout2'");
            await process.WriteLineAsync("echo -n 'hello stderr2' >&2");
            await process.WriteLineAsync("exit 0");

            (string? stdout, string? stderr) = await process.ReadToEndAsStringAsync(readStdout, readStderr);
            Assert.Equal(readStdout ? "hello stdout1hello stdout2" : null, stdout);
            Assert.Equal(readStderr ? "hello stderr1hello stderr2" : null, stderr);
        }

        [Theory]
        [MemberData(nameof(NewlineTestData))]
        public async Task ReadNewlines(string[] writeStrings, string[] readStrings)
        {
            using var client = await _sshServer.CreateClientAsync();
            using var process = await client.ExecuteAsync("bash");
            Func<Task> reader = async () =>
            {
                bool isError;
                string? s;
                foreach (var readString in readStrings)
                {
                    (isError, s) = await process.ReadLineAsync(readStdout: true, readStderr: false);
                    Assert.Equal(false, isError);
                    Assert.Equal(readString, s);
                }
                (isError, s) = await process.ReadLineAsync(readStdout: true, readStderr: false);
                Assert.Null(s);
                Assert.Equal(false, isError);
            };
            Task reading = reader();
            foreach (var writeString in writeStrings)
            {
                string echoCmd = "echo -n $'"
                                  + writeString.Replace("\r", "\\r").Replace("\n", "\\n")
                                  + "'";
                await process.WriteLineAsync(echoCmd);
                // Wait a little in order to make the client pick up the write separately.
                await Task.Delay(20);
            }
            await process.WriteLineAsync("exit 0");
            await reading;
        }

        public static IEnumerable<object[]> NewlineTestData
        {
            get
            {
                foreach (var data in RawData())
                {
                    yield return new object[] { data.writeStrings, data.readStrings };
                }

                static IEnumerable<(string[] writeStrings, string[] readStrings)> RawData()
                {
                    string[] expected;

                    // \r\n
                    expected = new[] { "line1", "line3" };
                    yield return (new[] { "line1\r\nline3" }, expected);

                    expected = new[] { "line1", "line2", "line3" };
                    yield return (new[] { "line1\r\nline2\r\nline3" }, expected);

                    // split between '\r' '\n'.
                    yield return (new[] { "line1\r", "\nline2\r", "\nline3" }, expected);
                    // \r
                    yield return (new[] { "line1\rline2\rline3" }, expected);
                    // \n
                    yield return (new[] { "line1\nline2\nline3" }, expected);

                    string longPrefix = new string('a', 8000);
                    // \r\n
                    expected = new[] { $"{longPrefix}line1", $"{longPrefix}line3" };
                    yield return (new[] { $"{longPrefix}line1\r\n{longPrefix}line3" }, expected);

                    expected = new[] { $"{longPrefix}line1", $"{longPrefix}line2", $"{longPrefix}line3" };
                    yield return (new[] { $"{longPrefix}line1\r\n{longPrefix}line2\r\n{longPrefix}line3" }, expected);

                    // split between '\r' '\n'.
                    yield return (new[] { $"{longPrefix}line1\r", $"\n{longPrefix}line2\r", $"\n{longPrefix}line3" }, expected);
                    // \r
                    yield return (new[] { $"{longPrefix}line1\r{longPrefix}line2\r{longPrefix}line3" }, expected);
                    // \n
                    yield return (new[] { $"{longPrefix}line1\n{longPrefix}line2\n{longPrefix}line3" }, expected);
                }
            }
        }
    }
}
