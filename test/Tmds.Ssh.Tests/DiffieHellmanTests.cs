using System.Numerics;
using Xunit;

namespace Tmds.Ssh.Tests;

public class DiffieHellmanTests
{
    [Theory]
    [InlineData(14, 2048)]
    [InlineData(16, 4096)]
    [InlineData(18, 8192)]
    public void GroupMatchesRfc3526(int id, int bitLength)
    {
        DiffieHellmanGroup group = GetGroup(id);
        BigInteger p = group.P;

        Assert.Equal(bitLength, group.PBitLength);
        Assert.Equal(new BigInteger(2), group.G);

        // The RFC 3526 primes start and end with 64 one bits.
        BigInteger mask = (BigInteger.One << 64) - BigInteger.One;
        Assert.Equal(mask, p & mask);
        Assert.Equal(mask, p >> (bitLength - 64));

        // Euler's criterion. This is only 1 when p is prime and the generator generates
        // the subgroup of order (p-1)/2, so a mistake in the prime would not pass this.
        BigInteger q = (p - BigInteger.One) / 2;
        Assert.Equal(BigInteger.One, BigInteger.ModPow(group.G, q, p));
    }

    [Theory]
    [InlineData(14)]
    [InlineData(16)]
    [InlineData(18)]
    public void KeyPairsAgreeOnSharedSecret(int id)
    {
        DiffieHellmanGroup group = GetGroup(id);

        var client = DiffieHellmanKeyExchange.KeyPair.Generate(group);
        var server = DiffieHellmanKeyExchange.KeyPair.Generate(group);

        Assert.True(group.IsValidPublicKey(client.PublicKey));
        Assert.True(group.IsValidPublicKey(server.PublicKey));
        Assert.NotEqual(client.PublicKey, server.PublicKey);

        Assert.Equal(
            BigInteger.ModPow(server.PublicKey, client.PrivateKey, group.P),
            BigInteger.ModPow(client.PublicKey, server.PrivateKey, group.P));
    }

    [Fact]
    public void RejectsInvalidPublicKeys()
    {
        DiffieHellmanGroup group = DiffieHellmanGroup.Group14;

        Assert.False(group.IsValidPublicKey(BigInteger.MinusOne));
        Assert.False(group.IsValidPublicKey(BigInteger.Zero));
        Assert.False(group.IsValidPublicKey(BigInteger.One));
        Assert.False(group.IsValidPublicKey(group.P - BigInteger.One));
        Assert.False(group.IsValidPublicKey(group.P));
        Assert.False(group.IsValidPublicKey(group.P + BigInteger.One));

        // Values with fewer than 4 bits set have a discrete logarithm that is trivial to compute.
        Assert.False(group.IsValidPublicKey(new BigInteger(2)));
        Assert.False(group.IsValidPublicKey(new BigInteger(0b1011)));
        Assert.True(group.IsValidPublicKey(new BigInteger(0b1111)));

        Assert.True(group.IsValidPublicKey(group.P - new BigInteger(2)));
    }

    [Fact]
    public void RejectsInvalidGroups()
    {
        DiffieHellmanGroup group14 = DiffieHellmanGroup.Group14;
        BigInteger two = new BigInteger(2);

        Assert.True(group14.IsValidGroup(minimumPBitLength: 2048));
        // The group is smaller than requested.
        Assert.False(group14.IsValidGroup(minimumPBitLength: 4096));
        // The modulus is negative.
        Assert.False(new DiffieHellmanGroup(-group14.P, two).IsValidGroup(2048));
        // The modulus is even.
        Assert.False(new DiffieHellmanGroup(group14.P + BigInteger.One, two).IsValidGroup(2048));
        // The generator is out of range.
        Assert.False(new DiffieHellmanGroup(group14.P, BigInteger.One).IsValidGroup(2048));
        Assert.False(new DiffieHellmanGroup(group14.P, group14.P - BigInteger.One).IsValidGroup(2048));
    }

    private static DiffieHellmanGroup GetGroup(int id)
        => id switch
        {
            14 => DiffieHellmanGroup.Group14,
            16 => DiffieHellmanGroup.Group16,
            18 => DiffieHellmanGroup.Group18,
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
}
