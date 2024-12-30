// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;

namespace Tmds.Ssh;

// ECDH Key Exchange: https://tools.ietf.org/html/rfc5656#section-4
class ECDHKeyExchange : KeyExchange
{
    private readonly ECCurve _ecCurve;
    private readonly HashAlgorithmName _hashAlgorithmName;

    public ECDHKeyExchange(ECCurve ecCurve, HashAlgorithmName hashAlgorithmName)
    {
        _ecCurve = ecCurve;
        _hashAlgorithmName = hashAlgorithmName;
    }

    public override async Task<KeyExchangeOutput> TryExchangeAsync(KeyExchangeContext context, IHostKeyVerification hostKeyVerification, Packet firstPacket, KeyExchangeInput input, ILogger logger, CancellationToken ct)
    {
        var sequencePool = context.SequencePool;
        var connectionInfo = input.ConnectionInfo;
        using ECDiffieHellman ecdh = ECDiffieHellman.Create(_ecCurve);

        // Send ECDH_INIT.
        using ECDiffieHellmanPublicKey myPublicKey = ecdh.PublicKey;
        ECPoint q_c = myPublicKey.ExportParameters().Q;
        await context.SendPacketAsync(CreateEcdhInitMessage(sequencePool, q_c), ct).ConfigureAwait(false);

        // Receive ECDH_REPLY.
        using Packet ecdhReplyMsg = await context.ReceivePacketAsync(MessageId.SSH_MSG_KEX_ECDH_REPLY, firstPacket.Move(), ct).ConfigureAwait(false);
        var ecdhReply = ParceEcdhReply(ecdhReplyMsg);

        // Verify received key is valid.
        PublicKey publicHostKey = await VerifyHostKeyAsync(hostKeyVerification, input, ecdhReply.public_host_key, ct).ConfigureAwait(false);

        // Compute shared secret.
        byte[] sharedSecret;
        try
        {
            sharedSecret = DeriveSharedSecret(ecdh, _ecCurve, ecdhReply.q_s);
        }
        catch (Exception ex)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Cannot determine shared secret.", connectionInfo, ex);
        }

        // Generate exchange hash.
        byte[] exchangeHash = CalculateExchangeHash(sequencePool, input.ConnectionInfo, input.ClientKexInitMsg, input.ServerKexInitMsg, ecdhReply.public_host_key.Data, q_c, ecdhReply.q_s, sharedSecret, _hashAlgorithmName);

        // Verify the server's signature.
        VerifySignature(publicHostKey, input.HostKeyAlgorithms, exchangeHash, ecdhReply.exchange_hash_signature, connectionInfo);

        return CalculateKeyExchangeOutput(input, sequencePool, sharedSecret, exchangeHash, _hashAlgorithmName);
    }

    private static byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, byte[] public_host_key, ECPoint q_c, ECPoint q_s, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName)
    {
        /*
            string   V_C, client's identification string (CR and LF excluded)
            string   V_S, server's identification string (CR and LF excluded)
            string   I_C, payload of the client's SSH_MSG_KEXINIT
            string   I_S, payload of the server's SSH_MSG_KEXINIT
            string   K_S, server's public host key
            string   Q_C, client's ephemeral public key octet string
            string   Q_S, server's ephemeral public key octet string
            mpint    K,   shared secret
         */
        using Sequence sequence = sequencePool.RentSequence();
        var writer = new SequenceWriter(sequence);
        writer.WriteString(connectionInfo.ClientIdentificationString!);
        writer.WriteString(connectionInfo.ServerIdentificationString!);
        writer.WriteString(clientKexInitMsg.Payload);
        writer.WriteString(serverKexInitMsg.Payload);
        writer.WriteString(public_host_key);
        writer.WriteString(q_c);
        writer.WriteString(q_s);
        writer.WriteString(sharedSecret);

        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithmName);
        foreach (var segment in sequence.AsReadOnlySequence())
        {
            hash.AppendData(segment.Span);
        }
        return hash.GetHashAndReset();
    }

    private static byte[] DeriveSharedSecret(ECDiffieHellman ecdh, ECCurve curve, ECPoint q)
    {
        ECParameters parameters = new ECParameters
        {
            Curve = curve,
            Q = q
        };
        using ECDiffieHellman peerEcdh = ECDiffieHellman.Create(parameters);
        using ECDiffieHellmanPublicKey peerPublicKey = peerEcdh.PublicKey;
        byte[] rawSecretAgreement = ecdh.DeriveRawSecretAgreement(peerPublicKey);
        var sharedSecret = rawSecretAgreement.ToBigInteger();
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret.ToMPIntByteArray();
    }

    private static Packet CreateEcdhInitMessage(SequencePool sequencePool, ECPoint q_c)
    {
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_KEX_ECDH_INIT);
        writer.WriteString(q_c);
        return packet.Move();
    }

    private static (
        SshKey public_host_key,
        ECPoint q_s,
        ReadOnlySequence<byte> exchange_hash_signature)
        ParceEcdhReply(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        reader.ReadMessageId(MessageId.SSH_MSG_KEX_ECDH_REPLY);
        SshKey public_host_key = reader.ReadSshKey();
        ECPoint q_s = reader.ReadStringAsECPoint();
        ReadOnlySequence<byte> exchange_hash_signature = reader.ReadStringAsBytes();
        reader.ReadEnd();
        return (
            public_host_key,
            q_s,
            exchange_hash_signature);
    }
}
