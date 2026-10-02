// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

sealed class CompressionAlgorithm
{
    private readonly Func<ICompressor> _createCompressor;
    private readonly Func<IDecompressor> _createDecompressor;

    private CompressionAlgorithm(Func<ICompressor> createCompressor, Func<IDecompressor> createDecompressor)
    {
        _createCompressor = createCompressor;
        _createDecompressor = createDecompressor;
    }

    public ICompressor CreateCompressor()
        => _createCompressor();

    public IDecompressor CreateDecompressor()
        => _createDecompressor();

    // Returns null when the packets are not compressed.
    public static CompressionAlgorithm? Find(Name name)
    {
        if (name == AlgorithmNames.None)
        {
            return null;
        }
        else if (name == AlgorithmNames.ZLibOpenSsh)
        {
            return new CompressionAlgorithm(
                static () => new ZLibCompressor(),
                static () => new ZLibDecompressor());
        }

        throw new NotSupportedException($"Compression algorithm '{name}' is not supported.");
    }
}
