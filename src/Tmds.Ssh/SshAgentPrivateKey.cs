// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.
using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class SshAgentPrivateKey : PrivateKey
{
    private readonly SshAgent _sshAgent;

    public SshAgentPrivateKey(SshAgent sshAgent, SshKeyData publicKey) :
        base(AlgorithmNames.GetSignatureAlgorithmsForKeyType(publicKey.Type), publicKey)
    {
        _sshAgent = sshAgent;
    }

    public override void Dispose()
    { }

    public override async ValueTask<byte[]> SignAsync(Name algorithm, byte[] data, CancellationToken cancellationToken)
    {
        if (Array.IndexOf(Algorithms, algorithm) == -1)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }

        byte[]? signature = await _sshAgent.TrySignAsync(algorithm, PublicKey.RawData, data, cancellationToken).ConfigureAwait(false);

        if (signature is null)
        {
            throw new CryptographicException("SSH Agent failed to sign.");
        }

        return signature;
    }
}
