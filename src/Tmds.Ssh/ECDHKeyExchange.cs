// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Reflection;
using System.Buffers.Binary;
using System.Numerics;

namespace Tmds.Ssh
{
    // ECDH Key Exchange: https://tools.ietf.org/html/rfc5656#section-4
    class ECDHKeyExchange : IKeyExchangeAlgorithm
    {
        private readonly ECCurve _ecCurve;
        private readonly HashAlgorithmName _hashAlgorithmName;

        public ECDHKeyExchange(Name algorithmName)
        {
            if (algorithmName == AlgorithmNames.EcdhSha2Nistp256)
            {
                (_ecCurve, _hashAlgorithmName) = (ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256);
            }
            else
            {
                throw new NotSupportedException($"Unknown algorithm name: {algorithmName}");
            }
        }

        public async Task<KeyExchangeOutput> TryExchangeAsync(SshConnection connection, KeyExchangeInput input, ILogger logger, CancellationToken ct)
        {
            var sequencePool = connection.SequencePool;

            // TODO: use input.HostKeyAlgorithms?

            using ECDiffieHellman ecdh = ECDiffieHellman.Create(_ecCurve);
            // Send ECDH_INIT.
            using ECDiffieHellmanPublicKey myPublicKey = ecdh.PublicKey;
            ECPoint q_c = myPublicKey.ExportParameters().Q;
            using var ecdhInitMsg = CreateEcdhInitMessage(sequencePool, q_c);
            await connection.SendPacketAsync(ecdhInitMsg.AsReadOnlySequence(), ct);

            Sequence? exchangeInitMsg = input.ExchangeInitMsg;
            // Receive ECDH_REPLY.
            if (exchangeInitMsg == null)
            {
                exchangeInitMsg = await connection.ReceivePacketAsync(ct);
            }
            if (exchangeInitMsg == null)
            {
                ThrowHelper.ThrowProtocolUnexpectedPeerClose();
            }
            var ecdhReply = ParceEcdhReply(exchangeInitMsg);

            // TODO: Verify received key is valid.
            // TODO: Verify host key belongs to server.

            // Compute shared secret.
            // TODO: what types of exceptions can we get when creating the public key?
            ECParameters parameters = new ECParameters
            {
                Curve = _ecCurve,
                Q = ecdhReply.q_s
            };
            using ECDiffieHellman peerEcdh = ECDiffieHellman.Create(parameters);
            using ECDiffieHellmanPublicKey peerPublicKey = peerEcdh.PublicKey;
            BigInteger sharedSecret = DeriveSharedSecret(ecdh, peerPublicKey);

            // Generate exchange hash.
            byte[] exchangeHash = CalculateExchangeHash(sequencePool, input.ConnectionInfo, input.ClientKexInitMsg, input.ServerKexInitMsg, ecdhReply.public_host_key, q_c, ecdhReply.q_s, sharedSecret);

            // TODO: verify the server's signature.

            byte[] sessionId = input.ConnectionInfo.SessionId ?? exchangeHash;
            byte[] initialIVC2S = Hash(sequencePool, sharedSecret, exchangeHash, (byte)'A', sessionId, input.InitialIVC2SLength);
            byte[] initialIVS2C = Hash(sequencePool, sharedSecret, exchangeHash, (byte)'B', sessionId, input.InitialIVS2CLength);
            byte[] encryptionKeyC2S = Hash(sequencePool, sharedSecret, exchangeHash, (byte)'C', sessionId, input.EncryptionKeyC2SLength);
            byte[] encryptionKeyS2C = Hash(sequencePool, sharedSecret, exchangeHash, (byte)'D', sessionId, input.EncryptionKeyS2CLength);
            byte[] integrityKeyC2S = Hash(sequencePool, sharedSecret, exchangeHash, (byte)'E', sessionId, input.IntegrityKeyC2SLength);
            byte[] integrityKeyS2C = Hash(sequencePool, sharedSecret, exchangeHash, (byte)'F', sessionId, input.IntegrityKeyS2CLength);

            return new KeyExchangeOutput(exchangeHash,
                initialIVS2C, encryptionKeyS2C, integrityKeyS2C,
                initialIVC2S, encryptionKeyC2S, integrityKeyC2S);
        }

        private byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, Sequence clientKexInitMsg, Sequence serverKexInitMsg, ReadOnlySequence<byte> public_host_key, ECPoint q_c, ECPoint q_s, BigInteger sharedSecret)
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
            writer.WriteString(clientKexInitMsg.AsReadOnlySequence());
            writer.WriteString(serverKexInitMsg.AsReadOnlySequence());
            writer.WriteString(public_host_key);
            writer.WriteString(q_c);
            writer.WriteString(q_s);
            writer.WriteMPInt(sharedSecret);

            using IncrementalHash hash = IncrementalHash.CreateHash(_hashAlgorithmName);
            foreach (var segment in sequence.AsReadOnlySequence())
            {
                hash.AppendData(segment.Span);
            }
            return hash.GetHashAndReset();
        }

        private byte[] Hash(SequencePool sequencePool, BigInteger sharedSecret, byte[] exchangeHash, byte c, byte[] sessionId, int hashLength)
        {
            // https://tools.ietf.org/html/rfc4253#section-7.2

            byte[] hashRv = new byte[hashLength];
            int hashOffset = 0;

            // TODO: handle 'If the key length needed is longer than the output of the HASH'
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
            Append(hashRv, K1, ref hashOffset);

            while (hashOffset != hashRv.Length)
            {
                // TODO: handle 'If the key length needed is longer than the output of the HASH'
                // K3 = HASH(K || H || K1 || K2)
                throw new NotSupportedException();
            }

            return hashRv;

            static void Append(byte[] key, byte[] append, ref int offset)
            {
                int available = Math.Min(append.Length, key.Length - offset);
                append.AsSpan().Slice(0, available).CopyTo(key.AsSpan(offset));
                offset += available;
            }
        }

        private BigInteger DeriveSharedSecret(ECDiffieHellman ecdh, ECDiffieHellmanPublicKey peerPublicKey)
        {
            // TODO: this uses Reflection on the OpenSSL implementation to figure out the shared key.
            // Can we use 'ECDiffieHellman.DeriveKeyFromHash' instead?

            var method = ecdh.GetType().GetMethod("DeriveSecretAgreement", BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { typeof(ECDiffieHellmanPublicKey), typeof(IncrementalHash) }, null);
            if (method != null)
            {
                object? rv = method.Invoke(ecdh, new[] { peerPublicKey, null });
                if (rv is byte[] sharedSecretArray)
                {
                    var sharedSecret = sharedSecretArray.ToBigInteger();
                    sharedSecretArray.AsSpan().Clear();
                    return sharedSecret;
                }
            }

            throw new NotSupportedException("Cannot determine private key.");
        }

        public void Dispose()
        { }

        private static Sequence CreateEcdhInitMessage(SequencePool sequencePool, ECPoint q_c)
        {
            using var writer = new SequenceWriter(sequencePool);
            writer.WriteByte(MessageNumber.SSH_MSG_KEX_ECDH_INIT);
            writer.WriteString(q_c);
            return writer.BuildSequence();
        }

        private static (
            ReadOnlySequence<byte> public_host_key,
            ECPoint q_s,
            ReadOnlySequence<byte> exchange_hash_signature)
            ParceEcdhReply(Sequence packet)
        {
            var reader = new SequenceReader(packet);
            reader.ReadByte(MessageNumber.SSH_MSG_KEX_ECDH_REPLY);
            ReadOnlySequence<byte> public_host_key = reader.ReadStringAsBytes();
            ECPoint q_s = reader.ReadStringAsECPoint();
            ReadOnlySequence<byte> exchange_hash_signature = reader.ReadStringAsBytes();
            reader.ReadEnd();
            return (
                public_host_key,
                q_s,
                exchange_hash_signature);
        }
    }
}