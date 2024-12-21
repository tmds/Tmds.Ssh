// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

abstract class PrivateKey : IDisposable
{
    private protected PrivateKey(Name[] algorithms, SshKey publicKey)
    {
        Algorithms = algorithms;
        PublicKey = publicKey;
    }

    public Name[] Algorithms { get; }
    public SshKey PublicKey { get; }

    public abstract void Dispose();

    public abstract void AppendSignature(Name algorithm, ref SequenceWriter writer, ReadOnlySequence<byte> data);
}
