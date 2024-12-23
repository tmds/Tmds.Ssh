// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.
namespace Tmds.Ssh;

sealed class SshAgentPrivateKey : PrivateKey
{
    private readonly SshAgent _sshAgent;

    public SshAgentPrivateKey(SshAgent sshAgent, SshKey publicKey) :
        base(GetAlgorithmsForKeyType(publicKey.Type), publicKey)
    {
        _sshAgent = sshAgent;
    }

    private static Name[] GetAlgorithmsForKeyType(Name keyType)
    {
        if (keyType == AlgorithmNames.SshRsa)
        {
            return AlgorithmNames.SshRsaAlgorithms;
        }
        else
        {
            return [ keyType ];
        }
    }

    public override void Dispose()
    { }

    public override async ValueTask<byte[]?> TrySignAsync(Name algorithm, byte[] data, CancellationToken cancellationToken)
    {
        if (Array.IndexOf(Algorithms, algorithm) == -1)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }

        return await _sshAgent.TrySignAsync(algorithm, PublicKey.Data, data, cancellationToken).ConfigureAwait(false);
    }
}
