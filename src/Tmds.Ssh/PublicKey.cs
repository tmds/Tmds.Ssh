// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Buffers;

namespace Tmds.Ssh;

abstract class PublicKey
{
    public static PublicKey CreateFromSshKey(HostKey key)
    {
        Name name = new Name(key.Type);
        if (name == AlgorithmNames.EcdsaSha2Nistp256)
        {
            return ECDsaPublicKey.CreateFromSshKey(key.RawKey);
        }
        else if (name == AlgorithmNames.SshRsa)
        {
            return RsaPublicKey.CreateFromSshKey(key.RawKey);
        }
        else
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return null;
        }
    }

    internal abstract bool VerifySignature(IReadOnlyList<Name> allowedAlgorithms, Span<byte> data, ReadOnlySequence<byte> signature);
}
