using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

abstract class KeyExchange<TKeyPair, TPublicKey> : IKeyExchangeAlgorithm
{
    public HashAlgorithmName HashAlgorithmName { get; }

    protected KeyExchange(HashAlgorithmName hashAlgorithmName)
    {
        HashAlgorithmName = hashAlgorithmName;
    }

    public async Task<KeyExchangeOutput> TryExchangeAsync(KeyExchangeContext context, IHostKeyAuthentication hostKeyAuthentication, Packet firstPacket, KeyExchangeInput input, ILogger logger, CancellationToken ct)
    {
        var sequencePool = context.SequencePool;
        var connectionInfo = input.ConnectionInfo;

        TKeyPair keyPair = GenerateKeyPair(context);
        try
        {
            await context.SendPacketAsync(CreateInitMessage(sequencePool, keyPair), ct).ConfigureAwait(false);

            // Receive reply message
            // All current key exchange algorithms use the same reply message ID (31)
            using Packet replyMsg = await context.ReceivePacketAsync(MessageId.SSH_MSG_KEX_ECDH_REPLY, firstPacket.Move(), ct).ConfigureAwait(false);
            var serverReply = ParseReplyMessage(replyMsg);

            await VerifyHostKeyAsync(hostKeyAuthentication, input, serverReply.publicHostKey, ct).ConfigureAwait(false);

            byte[] sharedSecret;
            try
            {
                sharedSecret = DeriveSharedSecret(keyPair, serverReply.serverPublicKey);
            }
            catch (Exception ex)
            {
                throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Cannot determine shared secret.", connectionInfo, ex);
            }

            byte[] exchangeHash = CalculateExchangeHash(sequencePool, input.ConnectionInfo, input.ClientKexInitMsg, input.ServerKexInitMsg, serverReply.publicHostKey.RawData, keyPair, serverReply.serverPublicKey, sharedSecret, HashAlgorithmName);

            VerifySignature(connectionInfo.ServerKey, input.HostKeyAlgorithms, exchangeHash, serverReply.exchangeHashSignature, connectionInfo);

            return CalculateKeyExchangeOutput(input, sequencePool, sharedSecret, exchangeHash, HashAlgorithmName);
        }
        finally
        {
            DisposeKeyPair(keyPair);
        }
    }

    protected abstract TKeyPair GenerateKeyPair(KeyExchangeContext context);
    protected abstract Packet CreateInitMessage(SequencePool sequencePool, TKeyPair keyPair);
    protected abstract (SshKeyData publicHostKey, TPublicKey serverPublicKey, ReadOnlySequence<byte> exchangeHashSignature) ParseReplyMessage(ReadOnlyPacket packet);
    protected abstract byte[] DeriveSharedSecret(TKeyPair clientKeyPair, TPublicKey serverPublicKey);
    protected abstract byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, ReadOnlyPacket clientKexInitMsg, ReadOnlyPacket serverKexInitMsg, ReadOnlyMemory<byte> public_host_key, TKeyPair clientKeyPair, TPublicKey serverPublicKey, byte[] sharedSecret, HashAlgorithmName hashAlgorithmName);
    protected abstract void DisposeKeyPair(TKeyPair keyPair);

    protected static async Task VerifyHostKeyAsync(IHostKeyAuthentication hostKeyAuthentication, KeyExchangeInput input, SshKeyData public_host_key, CancellationToken ct)
    {
        var connectionInfo = input.ConnectionInfo;

        // First.
        HostKeyVerification.CheckAllowedHostKeyAlgoritms(connectionInfo, public_host_key, input.HostKeyAlgorithms);

        HostKeyVerification.CheckMinimumRSAKeySize(connectionInfo, input.MinimumRSAKeySize);

        if (connectionInfo.ServerKey.CertificateInfo is not null)
        {
            HostKeyVerification.CheckCertificate(connectionInfo, connectionInfo.ServerKey.CertificateInfo, input.CASignatureAlgorithms);
        }

        // Last.
        await hostKeyAuthentication.AuthenticateAsync(connectionInfo, ct).ConfigureAwait(false);
    }

    protected static void VerifySignature(HostKey hostKey, IReadOnlyList<Name> allowedHostKeyAlgorithms, byte[] data, ReadOnlySequence<byte> signatureBlob, SshConnectionInfo connectionInfo)
    {
        var reader = new SequenceReader(signatureBlob);
        Name algorithmName = reader.ReadName();
        ReadOnlySequence<byte> signature = reader.ReadStringAsBytes();
        reader.ReadEnd();

        // Verify the signature algorithm is permitted by HostKeyAlgorithms.
        Name hostKeyAlgorithm = AlgorithmNames.GetHostKeyAlgorithmForSignatureAlgorithm(hostKey.ReceivedKeyType, algorithmName);
        if (!allowedHostKeyAlgorithms.Contains(hostKeyAlgorithm))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"Signature type {algorithmName} is not accepted.", connectionInfo);
        }

        if (!hostKey.PublicKey.VerifySignature(algorithmName, data, signature))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Signature does not match host key.", connectionInfo);
        }
    }

    protected static KeyExchangeOutput CalculateKeyExchangeOutput(KeyExchangeInput input, SequencePool sequencePool, byte[] sharedSecret, byte[] exchangeHash, HashAlgorithmName hashAlgorithmName)
    {
        byte[] sessionId = input.ConnectionInfo.SessionId ?? exchangeHash;
        byte[] initialIVC2S = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'A', sessionId, input.InitialIVC2SLength, hashAlgorithmName);
        byte[] initialIVS2C = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'B', sessionId, input.InitialIVS2CLength, hashAlgorithmName);
        byte[] encryptionKeyC2S = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'C', sessionId, input.EncryptionKeyC2SLength, hashAlgorithmName);
        byte[] encryptionKeyS2C = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'D', sessionId, input.EncryptionKeyS2CLength, hashAlgorithmName);
        byte[] integrityKeyC2S = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'E', sessionId, input.IntegrityKeyC2SLength, hashAlgorithmName);
        byte[] integrityKeyS2C = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'F', sessionId, input.IntegrityKeyS2CLength, hashAlgorithmName);

        return new KeyExchangeOutput(exchangeHash,
            initialIVS2C, encryptionKeyS2C, integrityKeyS2C,
            initialIVC2S, encryptionKeyC2S, integrityKeyC2S);
    }

    protected static byte[] CalculateKey(SequencePool sequencePool, byte[] sharedSecret, byte[] exchangeHash, byte c, byte[] sessionId, int keyLength, HashAlgorithmName hashAlgorithmName)
    {
        // https://tools.ietf.org/html/rfc4253#section-7.2

        byte[] key = new byte[keyLength];
        int keyOffset = 0;

        // HASH(K || H || c || session_id)
        using Sequence sequence = sequencePool.RentSequence();
        var writer = new SequenceWriter(sequence);
        writer.WriteString(sharedSecret);
        writer.Write(exchangeHash);
        writer.WriteByte(c);
        writer.Write(sessionId);

        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithmName);
        foreach (var segment in sequence.AsReadOnlySequence())
        {
            hash.AppendData(segment.Span);
        }
        byte[] K1 = hash.GetHashAndReset();
        Append(key, K1, ref keyOffset);

        while (keyOffset != key.Length)
        {
            sequence.Clear();

            // K3 = HASH(K || H || K1 || K2)
            writer = new SequenceWriter(sequence);
            writer.WriteString(sharedSecret);
            writer.Write(exchangeHash);
            writer.Write(key.AsSpan(0, keyOffset));

            foreach (var segment in sequence.AsReadOnlySequence())
            {
                hash.AppendData(segment.Span);
            }
            byte[] Kn = hash.GetHashAndReset();

            Append(key, Kn, ref keyOffset);
        }

        return key;

        static void Append(byte[] key, byte[] append, ref int offset)
        {
            int available = Math.Min(append.Length, key.Length - offset);
            append.AsSpan().Slice(0, available).CopyTo(key.AsSpan(offset));
            offset += available;
        }
    }
}