using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

abstract class KeyExchange : IKeyExchangeAlgorithm
{
    public abstract Task<KeyExchangeOutput> TryExchangeAsync(KeyExchangeContext context, IHostKeyAuthentication hostKeyAuthentication, Packet firstPacket, KeyExchangeInput input, ILogger logger, CancellationToken ct);

    protected static async Task VerifyHostKeyAsync(IHostKeyAuthentication hostKeyAuthentication, KeyExchangeInput input, SshKey public_host_key, CancellationToken ct)
    {
        var connectionInfo = input.ConnectionInfo;

        // First.
        HostKeyVerification.CheckAllowedHostKeyAlgoritms(connectionInfo, public_host_key, input.HostKeyAlgorithms);

        HostKeyVerification.CheckMinimumRSAKeySize(connectionInfo, input.MinimumRSAKeySize);

        if (connectionInfo.ServerKey.CertInfo is not null)
        {
            HostKeyVerification.CheckCertificate(connectionInfo, connectionInfo.ServerKey.CertInfo, input.CASignatureAlgorithms);
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
        Name hostKeyAlgorithm = AlgorithmNames.GetHostKeyAlgorithmForSignatureAlgorithm(hostKey.RawKey.Type, algorithmName);
        if (!allowedHostKeyAlgorithms.Contains(hostKeyAlgorithm))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"Signature type {algorithmName} is not accepted.", connectionInfo);
        }

        if (!hostKey.SignatureKey.VerifySignature(algorithmName, data, signature))
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

    protected virtual void Dispose(bool disposing)
    { }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}