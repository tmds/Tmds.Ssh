// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
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

        public abstract ValueTask<string> ReceiveLineAsync(int maxLength, CancellationToken ct);
        public abstract ValueTask WriteLineAsync(string line, CancellationToken ct);

        public abstract ValueTask<Sequence?> ReceivePacketAsync(CancellationToken ct, int maxLength = 0);
        public abstract ValueTask SendPacketAsync(ReadOnlySequence<byte> data, CancellationToken ct);
        public abstract void Dispose();
        public abstract void SetEncoderDecoder(PacketEncoder packetEncoder, PacketDecoder packetDecoder);
    }
}