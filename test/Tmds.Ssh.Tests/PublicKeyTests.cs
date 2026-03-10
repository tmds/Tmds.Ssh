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

    [Fact]
    public void EqualKeysAreEqual()
    {
        string typeName = "ecdh-sha2-nistp256";
        byte[] rawData = new byte[64];
        Random.Shared.NextBytes(rawData);

        PublicKey key1 = new PublicKey(typeName, rawData);
        PublicKey key2 = new PublicKey(typeName, rawData);

        Assert.True(key1.Equals(key2));
        Assert.True(key2.Equals(key1));
        Assert.Equal(key1.GetHashCode(), key2.GetHashCode());
    }

    [Fact]
    public void DifferentRawDataAreNotEqual()
    {
        string typeName = "ecdh-sha2-nistp256";
        byte[] rawData1 = new byte[64];
        byte[] rawData2 = new byte[64];
        Random.Shared.NextBytes(rawData1);
        Random.Shared.NextBytes(rawData2);

        PublicKey key1 = new PublicKey(typeName, rawData1);
        PublicKey key2 = new PublicKey(typeName, rawData2);

        Assert.False(key1.Equals(key2));
    }

    [Fact]
    public void DifferentTypesAreNotEqual()
    {
        byte[] rawData = new byte[64];
        Random.Shared.NextBytes(rawData);

        PublicKey key1 = new PublicKey("ecdh-sha2-nistp256", rawData);
        PublicKey key2 = new PublicKey("ssh-rsa", rawData);

        Assert.False(key1.Equals(key2));
    }

    [Fact]
    public void EqualsNullReturnsFalse()
    {
        PublicKey key = new PublicKey("ecdh-sha2-nistp256", new byte[64]);

        Assert.False(key.Equals(null));
    }
}
