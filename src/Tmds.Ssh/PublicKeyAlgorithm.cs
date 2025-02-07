// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;

namespace Tmds.Ssh;

abstract class PublicKeyAlgorithm
{
    public static PublicKeyAlgorithm CreateFromSshKey(SshKeyData key)
    {
        Name name = key.Type;
        if (name == AlgorithmNames.EcdsaSha2Nistp256 ||
            name == AlgorithmNames.EcdsaSha2Nistp384 ||
            name == AlgorithmNames.EcdsaSha2Nistp521)
        {
            return ECDsaPublicKey.CreateFromSshKey(key.RawData);
        }
        else if (name == AlgorithmNames.SshRsa)
        {
            return RsaPublicKey.CreateFromSshKey(key.RawData);
        }
        else if (name == AlgorithmNames.SshEd25519)
        {
            return Ed25519PublicKey.CreateFromSshKey(key.RawData);
        }
        else
        {
            ThrowHelper.ThrowDataUnexpectedValue();
            return null;
        }
    }

    internal abstract bool VerifySignature(Name algorithmName, ReadOnlySpan<byte> data, ReadOnlySequence<byte> signature);
}
