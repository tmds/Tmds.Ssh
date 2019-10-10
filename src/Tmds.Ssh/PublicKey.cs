// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Collections.Generic;

namespace Tmds.Ssh
{
    public abstract class PublicKey
    {
        private protected PublicKey(Name format)
        {
            Format = format;
        }

        internal static PublicKey Read(ReadOnlySequence<byte> data, IReadOnlyList<Name> allowedFormats)
        {
            var reader = new SequenceReader(data);
            var key = reader.ReadPublicKey(allowedFormats);
            reader.ReadEnd();
            return key;
        }

        internal abstract bool VerifySignature(Span<byte> data, ReadOnlySequence<byte> signature);

        internal Name Format { get; }
    }
}