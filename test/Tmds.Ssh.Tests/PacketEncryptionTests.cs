using System.Buffers;
using Xunit;

namespace Tmds.Ssh.Tests;

public class PacketEncryptionTests
{
    private const int MaxPacketLength = 32 * 1024;

    public static IEnumerable<object[]> CipherAndMacCombinations()
    {
        foreach (Name cipher in SshClientSettings.SupportedEncryptionAlgorithms)
        {
            if (PacketEncryptionAlgorithm.Find(cipher).IsAuthenticated)
            {
                yield return new object[] { cipher.ToString(), "" };
            }
            else
            {
                foreach (Name mac in SshClientSettings.SupportedMacAlgorithms)
                {
                    yield return new object[] { cipher.ToString(), mac.ToString() };
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(CipherAndMacCombinations))]
    public void RoundTrip(string cipherName, string macName)
    {
        var pool = new SequencePool();
        (IPacketEncryptor encryptor, IPacketDecryptor decryptor) = CreateEncryptorAndDecryptor(pool, cipherName, macName);

        using (encryptor)
        using (decryptor)
        {
            uint sequenceNumber = 3;

            // Use a range of payload lengths to exercise the various paddings.
            foreach (int payloadLength in Enumerable.Range(1, 200))
            {
                byte[] payload = CreatePayload(payloadLength);

                using Sequence wire = pool.RentSequence();
                encryptor.Encrypt(sequenceNumber, CreatePacket(pool, payload), wire);

                Assert.True(decryptor.TryDecrypt(wire, sequenceNumber, MaxPacketLength, out Packet decrypted));
                using (decrypted)
                {
                    Assert.Equal(payload, decrypted.Payload.ToArray());
                }
                Assert.Equal(0L, wire.Length);

                sequenceNumber++;
            }
        }
    }

    [Theory]
    [MemberData(nameof(CipherAndMacCombinations))]
    public void DecryptsWhenDataArrivesInParts(string cipherName, string macName)
    {
        var pool = new SequencePool();
        (IPacketEncryptor encryptor, IPacketDecryptor decryptor) = CreateEncryptorAndDecryptor(pool, cipherName, macName);

        using (encryptor)
        using (decryptor)
        {
            const uint sequenceNumber = 7;
            byte[] payload = CreatePayload(100);

            byte[] encrypted;
            using (Sequence wire = pool.RentSequence())
            {
                encryptor.Encrypt(sequenceNumber, CreatePacket(pool, payload), wire);
                encrypted = wire.AsReadOnlySequence().ToArray();
            }

            using Sequence receiveBuffer = pool.RentSequence();
            for (int i = 0; i < encrypted.Length - 1; i++)
            {
                Append(receiveBuffer, encrypted.AsSpan(i, 1));
                Assert.False(decryptor.TryDecrypt(receiveBuffer, sequenceNumber, MaxPacketLength, out Packet incomplete));
                Assert.True(incomplete.IsEmpty);
            }

            Append(receiveBuffer, encrypted.AsSpan(encrypted.Length - 1, 1));
            Assert.True(decryptor.TryDecrypt(receiveBuffer, sequenceNumber, MaxPacketLength, out Packet decrypted));
            using (decrypted)
            {
                Assert.Equal(payload, decrypted.Payload.ToArray());
            }
        }
    }

    [Theory]
    [MemberData(nameof(CipherAndMacCombinations))]
    public void ThrowsForTamperedPacket(string cipherName, string macName)
    {
        var pool = new SequencePool();
        (IPacketEncryptor encryptor, IPacketDecryptor decryptor) = CreateEncryptorAndDecryptor(pool, cipherName, macName);

        using (encryptor)
        using (decryptor)
        {
            const uint sequenceNumber = 11;

            using Sequence wire = pool.RentSequence();
            encryptor.Encrypt(sequenceNumber, CreatePacket(pool, CreatePayload(100)), wire);

            // Flip a bit in the encrypted payload.
            byte[] encrypted = wire.AsReadOnlySequence().ToArray();
            encrypted[encrypted.Length / 2] ^= 0x40;

            using Sequence receiveBuffer = pool.RentSequence();
            Append(receiveBuffer, encrypted);

            Assert.ThrowsAny<Exception>(() => decryptor.TryDecrypt(receiveBuffer, sequenceNumber, MaxPacketLength, out _));
        }
    }

    // Only the ciphers that use a MAC bind the packet to the sequence number in a way we can verify here.
    public static IEnumerable<object[]> CipherAndMacCombinationsWithMac()
        => CipherAndMacCombinations().Where(data => ((string)data[1]).Length > 0);

    [Theory]
    [MemberData(nameof(CipherAndMacCombinationsWithMac))]
    public void ThrowsForUnexpectedSequenceNumber(string cipherName, string macName)
    {
        var pool = new SequencePool();
        (IPacketEncryptor encryptor, IPacketDecryptor decryptor) = CreateEncryptorAndDecryptor(pool, cipherName, macName);

        using (encryptor)
        using (decryptor)
        {
            using Sequence wire = pool.RentSequence();
            encryptor.Encrypt(13, CreatePacket(pool, CreatePayload(100)), wire);

            Assert.ThrowsAny<Exception>(() => decryptor.TryDecrypt(wire, 14, MaxPacketLength, out _));
        }
    }

    private static (IPacketEncryptor, IPacketDecryptor) CreateEncryptorAndDecryptor(SequencePool pool, string cipherName, string macName)
    {
        PacketEncryptionAlgorithm encryptionAlgorithm = PacketEncryptionAlgorithm.Find(new Name(cipherName));
        HMacAlgorithm? macAlgorithm = encryptionAlgorithm.IsAuthenticated ? null : HMacAlgorithm.Find(new Name(macName));

        byte[] key = CreateRandomBytes(encryptionAlgorithm.KeyLength);
        byte[] iv = CreateRandomBytes(encryptionAlgorithm.IVLength);
        byte[] macKey = CreateRandomBytes(macAlgorithm?.KeyLength ?? 0);

        // The encryptor and decryptor each get their own arrays, like they do during the key exchange.
        return (encryptionAlgorithm.CreatePacketEncryptor(key.ToArray(), iv.ToArray(), macAlgorithm, macKey.ToArray()),
                encryptionAlgorithm.CreatePacketDecryptor(pool, key.ToArray(), iv.ToArray(), macAlgorithm, macKey.ToArray()));
    }

    private static Packet CreatePacket(SequencePool pool, byte[] payload)
    {
        var packet = new Packet(pool.RentSequence());
        packet.GetWriter().Write(payload);
        return packet;
    }

    private static byte[] CreatePayload(int length)
    {
        byte[] payload = new byte[length];
        Random.Shared.NextBytes(payload);
        // The first payload byte is the message id, use one that is valid.
        payload[0] = (byte)MessageId.SSH_MSG_DEBUG;
        return payload;
    }

    private static byte[] CreateRandomBytes(int length)
    {
        byte[] bytes = new byte[length];
        Random.Shared.NextBytes(bytes);
        return bytes;
    }

    private static void Append(Sequence sequence, ReadOnlySpan<byte> data)
    {
        data.CopyTo(sequence.AllocGetSpan(data.Length));
        sequence.AppendAlloced(data.Length);
    }
}
