using Xunit;

namespace Tmds.Ssh.Managed.Tests;

public class PublicKeyTests
{
    [Theory]
    [InlineData(1024)]
    [InlineData(1025)]
    [InlineData(1026)]
    [InlineData(1027)]
    public void PublicKeyToString(int length)
    {
        string typeName = "ecdh-sha2-nistp256";
        byte[] rawData = new byte[length];
        Random.Shared.NextBytes(rawData);

        PublicKey publicKey = new PublicKey(typeName, rawData);
        string expected = $"{typeName} {Convert.ToBase64String(rawData)}";
        Assert.Equal(expected, publicKey.ToString());
    }
}
