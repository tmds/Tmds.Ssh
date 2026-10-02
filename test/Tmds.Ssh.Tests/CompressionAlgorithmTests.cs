using System.Buffers;
using Xunit;

namespace Tmds.Ssh.Tests;

public class CompressionAlgorithmTests
{
    private const int MaxLength = 4 * 1024 * 1024;

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public void RoundTripsPayloads(string algorithmName)
    {
        using var session = new CompressionSession(algorithmName);

        foreach (int length in new[] { 1, 5, 100, 4096, 8192, 33000, 100_000 })
        {
            byte[] payload = CompressibleData(length);
            Assert.Equal(payload, session.RoundTrip(payload));
        }
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public void RoundTripsIncompressiblePayloads(string algorithmName)
    {
        using var session = new CompressionSession(algorithmName);

        // The compressed data is larger than the payload for random data.
        // These lengths make the decompressed data a multiple of the internal buffer size.
        foreach (int length in new[] { 4096, 8192, 16384 })
        {
            byte[] payload = new byte[length];
            Random.Shared.NextBytes(payload);
            Assert.Equal(payload, session.RoundTrip(payload));
        }
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public void RetainsCompressionContextAcrossPayloads(string algorithmName)
    {
        using var session = new CompressionSession(algorithmName);

        byte[] payload = CompressibleData(200);

        int firstLength = session.Compress(payload).Length;
        int secondLength = session.Compress(payload).Length;

        // The second payload is compressed using the context of the first one.
        Assert.True(secondLength < firstLength, $"Expected the second payload ({secondLength}) to be smaller than the first ({firstLength}).");
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public void DecompressThrowsWhenDecompressedDataExceedsMaxLength(string algorithmName)
    {
        using var session = new CompressionSession(algorithmName);

        byte[] compressed = session.Compress(CompressibleData(100_000));

        Assert.Throws<ProtocolException>(() => session.Decompress(compressed, maxLength: 35000));
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public void DecompressThrowsForInvalidData(string algorithmName)
    {
        using var session = new CompressionSession(algorithmName);

        byte[] invalid = new byte[100];
        Random.Shared.NextBytes(invalid);

        Assert.Throws<ProtocolException>(() => session.Decompress(invalid, MaxLength));
    }

    [Theory]
    [MemberData(nameof(CompressionAlgorithms))]
    public void DecompressedPacketPayloadIsReadable(string algorithmName)
    {
        // The decompressed data spans multiple buffers. Verify the packet header and the message id remain readable.
        using var session = new CompressionSession(algorithmName);

        byte[] payload = CompressibleData(20_000);
        payload[0] = (byte)MessageId.SSH_MSG_CHANNEL_DATA;

        byte[] compressed = session.Compress(payload);

        using Packet packet = session.DecompressToPacket(compressed);

        Assert.Equal(MessageId.SSH_MSG_CHANNEL_DATA, packet.MessageId);
        Assert.Equal(payload.Length, packet.PayloadLength);
        Assert.Equal(payload, packet.Payload.ToArray());
    }

    private static byte[] CompressibleData(int length)
    {
        byte[] data = new byte[length];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)('a' + (i % 26));
        }
        return data;
    }

    public static IEnumerable<object[]> CompressionAlgorithms()
        => SshClientSettings.SupportedCompressionAlgorithms
            .Where(name => name != AlgorithmNames.None)
            .Select(name => new object[] { name.ToString() });

    private sealed class CompressionSession : IDisposable
    {
        private readonly SequencePool _sequencePool = new SequencePool();
        private readonly ICompressor _compressor;
        private readonly IDecompressor _decompressor;

        public CompressionSession(string algorithmName)
        {
            var algorithm = CompressionAlgorithm.Find(new Name(algorithmName))!;
            _compressor = algorithm.CreateCompressor();
            _decompressor = algorithm.CreateDecompressor();
        }

        public byte[] Compress(byte[] payload)
        {
            using Sequence compressed = _sequencePool.RentSequence();
            _compressor.Compress(new ReadOnlySequence<byte>(payload), compressed);
            return compressed.AsReadOnlySequence().ToArray();
        }

        public byte[] Decompress(byte[] compressed, int maxLength)
        {
            using Sequence decompressed = _sequencePool.RentSequence();
            _decompressor.Decompress(new ReadOnlySequence<byte>(compressed), decompressed, maxLength);
            return decompressed.AsReadOnlySequence().ToArray();
        }

        public Packet DecompressToPacket(byte[] compressed)
        {
            Sequence sequence = _sequencePool.RentSequence();
            Packet packet = new Packet(sequence);
            _decompressor.Decompress(new ReadOnlySequence<byte>(compressed), sequence, MaxLength);
            return packet;
        }

        public byte[] RoundTrip(byte[] payload)
            => Decompress(Compress(payload), MaxLength);

        public void Dispose()
        {
            _compressor.Dispose();
            _decompressor.Dispose();
        }
    }
}
