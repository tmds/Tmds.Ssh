// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Collections.Generic;

namespace Tmds.Ssh.Managed
{
    abstract class PublicKey
    {
        public static PublicKey CreateFromSshKey(SshKey key)
        {
            Name name = new Name(key.Type);
            if (name == AlgorithmNames.EcdsaSha2Nistp256)
            {
                return ECDsaPublicKey.CreateFromSshKey(key.RawKey);
            }
            else
            {
                ThrowHelper.ThrowProtocolUnexpectedValue();
                return null;
            }
        }

        internal abstract bool VerifySignature(Span<byte> data, ReadOnlySequence<byte> signature);
    }
}