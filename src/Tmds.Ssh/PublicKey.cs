// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Collections.Generic;

namespace Tmds.Ssh
{
    abstract class PublicKey
    {
        public static PublicKey CreateFromSshKey(SshKey key)
        {
            if (new Name(key.Type) == AlgorithmNames.SshRsa) // TODO...
            {
                return RsaPublicKey.CreateFromSshKey(key.Data);
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