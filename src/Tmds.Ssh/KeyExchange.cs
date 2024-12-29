﻿using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Tmds.Ssh;

abstract class KeyExchange
{
    protected readonly HashAlgorithmName _hashAlgorithmName;

    public KeyExchange(HashAlgorithmName hashAlgorithmName)
    {
        this._hashAlgorithmName = hashAlgorithmName;
    }

    public static async Task<PublicKey> VerifyHostKeyAsync(IHostKeyVerification hostKeyVerification, KeyExchangeInput input, SshKey public_host_key, CancellationToken ct)
    {
        var connectionInfo = input.ConnectionInfo;
        connectionInfo.ServerKey = new HostKey(public_host_key);
        await hostKeyVerification.VerifyAsync(connectionInfo, ct).ConfigureAwait(false);

        var publicHostKey = PublicKey.CreateFromSshKey(public_host_key);
        if (publicHostKey is RsaPublicKey rsaPublicKey && rsaPublicKey.KeySize < input.MinimumRSAKeySize)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, $"Server RSA key size {rsaPublicKey.KeySize} is less than {input.MinimumRSAKeySize}.", connectionInfo);
        }

        return publicHostKey;
    }

    public static void VerifySignature(PublicKey publicHostKey, IReadOnlyList<Name> allowedAlgorithms, byte[] exchangeHash, ReadOnlySequence<byte> exchange_hash_signature, SshConnectionInfo connectionInfo)
    {
        if (!publicHostKey.VerifySignature(allowedAlgorithms, exchangeHash, exchange_hash_signature))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Signature does not match host key.", connectionInfo);
        }
    }

    public KeyExchangeOutput CalculateKeyExchangeOutput(KeyExchangeInput input, SequencePool sequencePool, BigInteger sharedSecret, byte[] exchangeHash)
    {
        byte[] sessionId = input.ConnectionInfo.SessionId ?? exchangeHash;
        byte[] initialIVC2S = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'A', sessionId, input.InitialIVC2SLength);
        byte[] initialIVS2C = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'B', sessionId, input.InitialIVS2CLength);
        byte[] encryptionKeyC2S = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'C', sessionId, input.EncryptionKeyC2SLength);
        byte[] encryptionKeyS2C = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'D', sessionId, input.EncryptionKeyS2CLength);
        byte[] integrityKeyC2S = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'E', sessionId, input.IntegrityKeyC2SLength);
        byte[] integrityKeyS2C = CalculateKey(sequencePool, sharedSecret, exchangeHash, (byte)'F', sessionId, input.IntegrityKeyS2CLength);

        return new KeyExchangeOutput(exchangeHash,
            initialIVS2C, encryptionKeyS2C, integrityKeyS2C,
            initialIVC2S, encryptionKeyC2S, integrityKeyC2S);
    }

    private byte[] CalculateKey(SequencePool sequencePool, BigInteger sharedSecret, byte[] exchangeHash, byte c, byte[] sessionId, int keyLength)
    {
        // https://tools.ietf.org/html/rfc4253#section-7.2

        byte[] key = new byte[keyLength];
        int keyOffset = 0;

        // HASH(K || H || c || session_id)
        using Sequence sequence = sequencePool.RentSequence();
        var writer = new SequenceWriter(sequence);
        writer.WriteMPInt(sharedSecret);
        writer.Write(exchangeHash);
        writer.WriteByte(c);
        writer.Write(sessionId);

        using IncrementalHash hash = IncrementalHash.CreateHash(_hashAlgorithmName);
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
            writer.WriteMPInt(sharedSecret);
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