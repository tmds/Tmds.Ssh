// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// Represents an established connection.
// Handles encryption, compression and integrity verification.
// Binary packet protocol: https://tools.ietf.org/html/rfc4253#section-6.
abstract class SshConnection : IDisposable
{
    protected SshConnection(SequencePool sequencePool)
    {
        SequencePool = sequencePool ?? throw new ArgumentNullException(nameof(sequencePool));
    }

    public SequencePool SequencePool { get; }

    public abstract void EnableKeepAlive(int period, Action callback);

    public abstract ValueTask<string> ReceiveLineAsync(int maxLength, CancellationToken ct);
    public abstract ValueTask WriteLineAsync(string line, CancellationToken ct);

    public abstract ValueTask<Packet> ReceivePacketAsync(CancellationToken ct, int maxLength = Constants.PreAuthMaxPacketLength);
    public abstract ValueTask SendPacketAsync(Packet packet, CancellationToken ct);
    public abstract void Dispose();
    public abstract void SetEncryptorDecryptor(IPacketEncryptor packetEncoder, IPacketDecryptor packetDecoder);
}
