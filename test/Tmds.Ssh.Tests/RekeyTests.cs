using Xunit.Sdk;

namespace Tmds.Ssh.Tests;

[Collection(nameof(RekeySshServerCollection))]
public class RekeyTests
{
    private readonly RekeySshServer _sshServer;

    public RekeyTests(RekeySshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task HandlesServerInitiatedRekey()
    {
        using var client = await _sshServer.CreateClientAsync();

        // Use cat to echo back what we write
        using var process = await client.ExecuteAsync("cat");

        // Transfer data in a loop to trigger rekeying multiple times with the server configured RekeyLimit (16K).
        const int iterations = 100;
        const int messageSize = 1024;
        byte[] sendBuffer = new byte[messageSize];
        for (int i = 0; i < messageSize; i++)
        {
            sendBuffer[i] = (byte)('A' + (i % 26));
        }

        var writeTask = Task.Run(async () =>
        {
            for (int i = 0; i < iterations; i++)
            {
                await process.WriteAsync(sendBuffer);
            }
            process.WriteEof();
        });

        var readTask = Task.Run(async () =>
        {
            byte[] receiveBuffer = new byte[messageSize / 3];
            int totalBytesRead = 0;
            int expectedTotalBytes = messageSize * iterations;

            while (totalBytesRead < expectedTotalBytes)
            {
                (bool isError, int bytesRead) = await process.ReadAsync(receiveBuffer, receiveBuffer);

                Assert.False(isError, "Expected stdout, got stderr");
                Assert.True(bytesRead > 0, "Expected data, got 0 bytes");

                // Verify we got the expected data
                for (int i = 0; i < bytesRead; i++)
                {
                    int expectedIndex = (totalBytesRead + i) % messageSize;
                    Assert.Equal(sendBuffer[expectedIndex], receiveBuffer[i]);
                }

                totalBytesRead += bytesRead;
            }
        });

        await Task.WhenAll(writeTask, readTask);

        int exitCode = await process.GetExitCodeAsync();
        Assert.Equal(0, exitCode);
    }
}

public class RekeySshServer : SshServer
{
    // Set a low RekeyLimit to force frequent rekeying during tests
    // Format: "default 16K" means rekey after 16KB of data transferred
    // The "default" applies to both incoming and outgoing data
    public const string Config =
        """
        RekeyLimit 16K
        """;

    public RekeySshServer(IMessageSink messageSink) :
        base(Config, messageSink)
    {
    }
}

[CollectionDefinition(nameof(RekeySshServerCollection))]
public class RekeySshServerCollection : ICollectionFixture<RekeySshServer>
{
    // This class has no code, and is never created. Its purpose is simply
    // to be the place to apply [CollectionDefinition] and all the
    // ICollectionFixture<> interfaces.
}
