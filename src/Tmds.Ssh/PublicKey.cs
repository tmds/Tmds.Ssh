// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

abstract class PublicKey
{
    public static PublicKey CreateFromSshKey(SshKey key)
    {
        Name name = key.Type;
        if (name == AlgorithmNames.EcdsaSha2Nistp256 ||
            name == AlgorithmNames.EcdsaSha2Nistp384 ||
            name == AlgorithmNames.EcdsaSha2Nistp521)
        {
            return ECDsaPublicKey.CreateFromSshKey(key.Data);
        }
        else if (name == AlgorithmNames.SshRsa)
        {
            return RsaPublicKey.CreateFromSshKey(key.Data);
        }
        else if (name == AlgorithmNames.SshEd25519)
        {
            return Ed25519PublicKey.CreateFromSshKey(key.Data);
        }
        else
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return null;
        }
    }

    public static ReadOnlySpan<Name> AlgorithmsForKeyType(ref Name keyType)
    {
        if (keyType == AlgorithmNames.SshRsa)
        {
            return AlgorithmNames.SshRsaAlgorithms;
        }
        else
        {
            return new ReadOnlySpan<Name>(ref keyType);
        }
    }

    internal abstract bool VerifySignature(IReadOnlyList<Name> allowedAlgorithms, Span<byte> data, ReadOnlySequence<byte> signature);
}
