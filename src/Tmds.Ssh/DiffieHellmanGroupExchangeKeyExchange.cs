// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Numerics;
using System.Security.Cryptography;

namespace Tmds.Ssh;

// Diffie-Hellman Group and Key Exchange: https://www.rfc-editor.org/rfc/rfc4419
// The server picks the group instead of it being fixed by the algorithm name.
sealed class DiffieHellmanGroupExchangeKeyExchange(HashAlgorithmName hashAlgorithmName) : DiffieHellmanKeyExchange(hashAlgorithmName)
{
    // Groups smaller than 2048 bits are not considered secure. This matches OpenSSH's DH_GRP_MIN.
    private const uint MinimumGroupSize = 2048;
    private const uint PreferredGroupSize = 3072;
    private const uint MaximumGroupSize = 8192;

    private DiffieHellmanGroup? _group;

    protected override DiffieHellmanGroup Group => _group!;

    protected override MessageId InitMessageId => MessageId.SSH_MSG_KEX_DH_GEX_INIT;

    protected override MessageId ReplyMessageId => MessageId.SSH_MSG_KEX_DH_GEX_REPLY;

    // Negotiate the group before the key pair is generated.
    protected override async ValueTask<Packet> PrepareAsync(KeyExchangeContext context, Packet firstPacket, CancellationToken ct)
    {
        SequencePool sequencePool = context.SequencePool;

        await context.SendPacketAsync(CreateGroupRequestMessage(sequencePool), ct).ConfigureAwait(false);

        using Packet groupMsg = await context.ReceivePacketAsync(MessageId.SSH_MSG_KEX_DH_GEX_GROUP, firstPacket.Move(), ct).ConfigureAwait(false);
        (BigInteger p, BigInteger g) = ParseGroupMessage(groupMsg);

        var group = new DiffieHellmanGroup(p, g);
        if (!group.IsValidGroup((int)MinimumGroupSize) || group.PBitLength > MaximumGroupSize)
        {
            throw new ProtocolException($"The server proposed an unacceptable Diffie-Hellman group of {group.PBitLength} bits.");
        }
        _group = group;

        // The reply is received by the base class.
        return default;
    }

    protected override void WriteGroupExchangeParameters(ref SequenceWriter writer)
    {
        /*
            uint32    min, minimal size in bits of an acceptable group
            uint32    n, preferred size in bits of the group the server will send
            uint32    max, maximal size in bits of an acceptable group
            mpint     p, safe prime
            mpint     g, generator for subgroup
         */
        DiffieHellmanGroup group = Group;
        writer.WriteUInt32(MinimumGroupSize);
        writer.WriteUInt32(PreferredGroupSize);
        writer.WriteUInt32(MaximumGroupSize);
        writer.WriteMPInt(group.P);
        writer.WriteMPInt(group.G);
    }

    private static Packet CreateGroupRequestMessage(SequencePool sequencePool)
    {
        /*
            byte      SSH_MSG_KEX_DH_GEX_REQUEST
            uint32    min
            uint32    n
            uint32    max
         */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_KEX_DH_GEX_REQUEST);
        writer.WriteUInt32(MinimumGroupSize);
        writer.WriteUInt32(PreferredGroupSize);
        writer.WriteUInt32(MaximumGroupSize);
        return packet.Move();
    }

    private static (BigInteger p, BigInteger g) ParseGroupMessage(ReadOnlyPacket packet)
    {
        /*
            byte      SSH_MSG_KEX_DH_GEX_GROUP
            mpint     p, safe prime
            mpint     g, generator for subgroup in GF(p)
         */
        var reader = packet.GetReader();
        reader.ReadMessageId(MessageId.SSH_MSG_KEX_DH_GEX_GROUP);
        BigInteger p = reader.ReadMPInt();
        BigInteger g = reader.ReadMPInt();
        reader.ReadEnd();
        return (p, g);
    }
}
