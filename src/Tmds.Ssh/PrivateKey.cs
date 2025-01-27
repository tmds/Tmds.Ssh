// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

abstract class PrivateKey : IDisposable
{
    private protected PrivateKey(Name[] algorithms, SshKeyData publicKey)
    {
        Algorithms = algorithms;
        PublicKey = publicKey;
    }

    public Name[] Algorithms { get; }
    public SshKeyData PublicKey { get; }

    public abstract void Dispose();

    public abstract ValueTask<byte[]> SignAsync(Name algorithm, byte[] data, CancellationToken cancellationToken);
}
