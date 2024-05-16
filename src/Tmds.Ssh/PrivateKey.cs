// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;

namespace Tmds.Ssh
{
    abstract class PrivateKey : IDisposable
    {
        private protected PrivateKey(Name format)
        {
            Format = format;
        }

        public Name Format { get; }

        public abstract void Dispose();

        public abstract void AppendPublicKey(ref SequenceWriter writer);
        public abstract void AppendSignature(ref SequenceWriter writer, ReadOnlySequence<byte> data);
    }
}