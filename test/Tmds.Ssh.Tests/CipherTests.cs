using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class CipherTests
{
    private readonly SshServer _sshServer;

    public CipherTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task ConnectWithDecryptionCipher(string cipher)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings => settings.EncryptionAlgorithmsClientToServer = [ new Name(cipher) ]
        );
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task ConnectWithEncryptionCipher(string cipher)
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings => settings.EncryptionAlgorithmsServerToClient = [ new Name(cipher) ]
        );
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task Padding(string cipher)
    {
        using var client = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.EncryptionAlgorithmsServerToClient = [ new Name(cipher) ];
                settings.EncryptionAlgorithmsServerToClient = [ new Name(cipher) ];
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

    public static IEnumerable<object[]> Ciphers()
        => SshClientSettings.SupportedEncryptionAlgorithms.Select(name => new [] { name.ToString() });
}
