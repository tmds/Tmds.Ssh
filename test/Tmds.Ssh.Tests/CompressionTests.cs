using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class CompressionTests
{
    private readonly SshServer _sshServer;

    public CompressionTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public async Task ConnectWithCompressionEnabled(string algorithm)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.EnableCompression = true;
                settings.CompressionAlgorithmsClientToServer = [ algorithm, "none" ];
                settings.CompressionAlgorithmsServerToClient = [ algorithm, "none" ];
            }
        );
    }

    [Fact]
    public async Task CompressionAlgorithmsAreNotUsedWhenCompressionIsNotEnabled()
    {
        // The algorithms are not used, so an algorithm the server doesn't support doesn't prevent connecting.
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.CompressionAlgorithmsClientToServer = [ "dummy-algorithm" ];
                settings.CompressionAlgorithmsServerToClient = [ "dummy-algorithm" ];
            }
        );
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public async Task ConnectWithCompressionClientToServer(string algorithm)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.EnableCompression = true;
                settings.CompressionAlgorithmsClientToServer = [ algorithm, "none" ];
            }
        );
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public async Task ConnectWithCompressionServerToClient(string algorithm)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.EnableCompression = true;
                settings.CompressionAlgorithmsServerToClient = [ algorithm, "none" ];
            }
        );
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public async Task ConnectWithCompressionSkipsUnknown(string algorithm)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.EnableCompression = true;
                settings.CompressionAlgorithmsClientToServer = [ "dummy-algorithm", algorithm, "none" ];
                settings.CompressionAlgorithmsServerToClient = [ "dummy-algorithm", algorithm, "none" ];
            }
        );
    }

    [Fact]
    public async Task ConnectFailsWhenNoCommonCompressionAlgorithm()
    {
        await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(
                settings =>
                {
                    settings.EnableCompression = true;
                    settings.CompressionAlgorithmsClientToServer = [ "dummy-algorithm" ];
                }
            ));
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithmsAndCompressibility))]
    public async Task DataRoundTrips(string algorithm, bool compressible)
    {
        using var client = await CreateCompressingClientAsync(algorithm);

        using var process = await client.ExecuteAsync("cat");

        // Include sizes that span multiple channel packets.
        foreach (int length in new[] { 1, 100, 4096, 40_000, 100_000 })
        {
            byte[] sendBuffer = new byte[length];
            if (compressible)
            {
                for (int i = 0; i < sendBuffer.Length; i++)
                {
                    sendBuffer[i] = (byte)('a' + (i % 26));
                }
            }
            else
            {
                Random.Shared.NextBytes(sendBuffer);
            }

            var writeTask = process.WriteAsync(sendBuffer).AsTask();

            byte[] receiveBuffer = new byte[length];
            int receiveBufferOffset = 0;
            do
            {
                Memory<byte> dst = receiveBuffer.AsMemory(receiveBufferOffset);
                (bool isError, int bytesRead) = await process.ReadAsync(dst, dst);
                Assert.False(isError);
                Assert.NotEqual(0, bytesRead);
                receiveBufferOffset += bytesRead;
            } while (receiveBufferOffset != receiveBuffer.Length);

            await writeTask;

            Assert.Equal(sendBuffer, receiveBuffer);
        }
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public async Task CompressionStartsAfterAuthentication(string algorithm)
    {
        // 'zlib@openssh.com' only starts compressing after the user has authenticated.
        // Verify the messages that are exchanged before and after that point.
        using var client = await CreateCompressingClientAsync(algorithm);

        using var process = await client.ExecuteAsync("echo hello");

        (string stdout, string stderr) = await process.ReadToEndAsStringAsync();

        Assert.Equal("hello\n", stdout);
        Assert.Equal("", stderr);
        Assert.Equal(0, await process.GetExitCodeAsync());
    }

    [Fact]
    public async Task ConnectWithCompressionEnabledThroughSshConfig()
    {
        var options = new SshConfigSettings()
        {
            ConfigFilePaths = [],
            Options = new Dictionary<SshConfigOption, SshConfigOptionValue>()
            {
                { SshConfigOption.Hostname, "localhost" },
                { SshConfigOption.User, _sshServer.TestUser },
                { SshConfigOption.Port, _sshServer.ServerPort.ToString() },
                { SshConfigOption.IdentityFile, _sshServer.TestUserIdentityFile },
                { SshConfigOption.StrictHostKeyChecking, "no" },
                { SshConfigOption.UserKnownHostsFile, Path.Combine(Path.GetTempPath(), Path.GetTempFileName()) },
                { SshConfigOption.Compression, "yes" },
            }
        };

        using var client = new SshClient("dummy", options);
        await client.ConnectAsync();

        using var process = await client.ExecuteAsync("echo hello");
        (string stdout, _) = await process.ReadToEndAsStringAsync();
        Assert.Equal("hello\n", stdout);
    }

    private Task<SshClient> CreateCompressingClientAsync(string algorithm)
        => _sshServer.CreateClientAsync(
            settings =>
            {
                settings.EnableCompression = true;
                settings.CompressionAlgorithmsClientToServer = [ algorithm, "none" ];
                settings.CompressionAlgorithmsServerToClient = [ algorithm, "none" ];
            }
        );

    public static IEnumerable<object[]> CompressionAlgorithms()
        => SshClientSettings.SupportedCompressionAlgorithms
            .Where(name => name != AlgorithmNames.None)
            .Select(name => new object[] { name.ToString() });

    public static IEnumerable<object[]> CompressionAlgorithmsAndCompressibility()
        => CompressionAlgorithms().SelectMany(args => new[] {
            new object[] { args[0], true },
            new object[] { args[0], false }
        });
}
