using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class MacTests
{
    // The MAC algorithms are only used with ciphers that are not authenticated.
    private const string CipherWithMac = "aes256-ctr";

    private readonly SshServer _sshServer;

    public MacTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [MemberData(nameof(Macs))]
    public async Task ConnectWithDecryptionMac(string mac)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.EncryptionAlgorithmsServerToClient = [ CipherWithMac ];
                settings.MacAlgorithmsServerToClient = [ mac ];
            }
        );
    }

    [Theory]
    [MemberData(nameof(Macs))]
    public async Task ConnectWithEncryptionMac(string mac)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.EncryptionAlgorithmsClientToServer = [ CipherWithMac ];
                settings.MacAlgorithmsClientToServer = [ mac ];
            }
        );
    }

    [Theory]
    [MemberData(nameof(Macs))]
    public async Task Padding(string mac)
    {
        using var client = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.EncryptionAlgorithmsServerToClient = [ CipherWithMac ];
                settings.EncryptionAlgorithmsClientToServer = [ CipherWithMac ];
                settings.MacAlgorithmsServerToClient = [ mac ];
                settings.MacAlgorithmsClientToServer = [ mac ];
            }
        );

        using var process = await client.ExecuteAsync("cat");

        // We increment by one over a range to test various paddings.
        foreach (int length in Enumerable.Range(1, 128))
        {
            byte[] sendBuffer = new byte[length];
            Random.Shared.NextBytes(sendBuffer);
            await process.WriteAsync(sendBuffer);

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

            Assert.Equal(sendBuffer, receiveBuffer);
        }
    }

    [Fact]
    public async Task ConnectFailsWhenNoSupportedMac()
    {
        await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(
                settings =>
                {
                    settings.EncryptionAlgorithmsClientToServer = [ CipherWithMac ];
                    settings.MacAlgorithmsClientToServer = [ "dummy-algorithm" ];
                }
            ));
    }

    public static IEnumerable<object[]> Macs()
        => SshClientSettings.SupportedMacAlgorithms.Select(name => new [] { name.ToString() });
}
