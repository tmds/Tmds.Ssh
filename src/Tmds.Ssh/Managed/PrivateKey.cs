// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Collections.Immutable;

namespace Tmds.Ssh.Managed;

abstract class PrivateKey : IDisposable
{
    private protected PrivateKey(ImmutableArray<Name> algorithms)
    {
        Algorithms = algorithms;
    }

    public ImmutableArray<Name> Algorithms { get; }

    public abstract void Dispose();

    public abstract void AppendPublicKey(ref SequenceWriter writer);
    public abstract void AppendSignature(Name algorithm, ref SequenceWriter writer, ReadOnlySequence<byte> data);
}
