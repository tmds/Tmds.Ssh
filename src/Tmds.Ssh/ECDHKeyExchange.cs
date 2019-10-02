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

        public async Task<KeyExchangeOutput> TryExchangeAsync(IReadOnlyList<Name> hostKeyAlgorithms, Sequence? initialMessage, Sequence clientInit, Sequence serverInit, SshConnection connection, SshConnectionInfo connectionInfo, ILogger logger, CancellationToken ct)
        {
            // TODO: use hostKeyAlgorithms?
            using ECDiffieHellman ecdh = ECDiffieHellman.Create(_ecCurve);
            // Send ECDH_INIT.
            using ECDiffieHellmanPublicKey myPublicKey = ecdh.PublicKey;
            ECPoint q_c = myPublicKey.ExportParameters().Q;
            using var initMessage = CreateEcdhInitMessage(connection.SequencePool, q_c);
            await connection.SendPacketAsync(initMessage.AsReadOnlySequence(), ct);

            // Receive ECDH_REPLY.
            if (initialMessage == null)
            {
                initialMessage = await connection.ReceivePacketAsync(ct);
            }
            if (initialMessage == null)
            {
                ThrowHelper.ThrowProtocolUnexpectedPeerClose();
            }
            var ecdhReply = ParceEcdhReply(initialMessage);

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
            byte[] exchangeHash = CalculateExchangeHash(connection.SequencePool, connectionInfo, clientInit, serverInit, ecdhReply.public_host_key, q_c, ecdhReply.q_s, sharedSecret);

            // TODO: verify the server's signature.

            byte[] sessionId = connectionInfo.SessionId ?? exchangeHash;
            byte[] initialIV = Hash(sharedSecret, exchangeHash, (byte)'A', sessionId);
            byte[] encryptionKey = Hash(sharedSecret, exchangeHash, (byte)'C', sessionId);
            byte[] integrityKey = Hash(sharedSecret, exchangeHash, (byte)'E', sessionId);

            return new KeyExchangeOutput(exchangeHash, initialIV, encryptionKey, integrityKey);
        }

        private byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, Sequence clientInit, Sequence serverInit, ReadOnlySequence<byte> public_host_key, ECPoint q_c, ECPoint q_s, BigInteger sharedSecret)
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
            writer.WriteString(clientInit.AsReadOnlySequence());
            writer.WriteString(serverInit.AsReadOnlySequence());
            writer.WriteString(public_host_key);
            writer.WriteECPoint(q_c);
            writer.WriteECPoint(q_s);
            writer.WriteMPInt(sharedSecret);

            using IncrementalHash hash = IncrementalHash.CreateHash(_hashAlgorithmName);
            foreach (var segment in sequence.AsReadOnlySequence())
            {
                hash.AppendData(segment.Span);
            }
            return hash.GetHashAndReset();
        }

        private byte[] Hash(BigInteger sharedSecret, byte[] exchangeHash, byte c, byte[] sessionId)
        {
            // https://tools.ietf.org/html/rfc4253#section-7.2
            // TODO: handle 'If the key length needed is longer than the output of the HASH'

            int sharedSecretLength = sharedSecret.GetByteCount(isUnsigned: false);
            int spanLength = Math.Max(sharedSecretLength, 4);
            Span<byte> span = spanLength <= Constants.StackallocThreshold ? stackalloc byte[spanLength] : new byte[spanLength];

            // HASH(K || H || "?" || session_id)
            using IncrementalHash hash = IncrementalHash.CreateHash(_hashAlgorithmName);

            // K is encoded as mpint
            BinaryPrimitives.WriteUInt32BigEndian(span, (uint)sharedSecretLength);
            hash.AppendData(span.Slice(0, 4));
            sharedSecret.TryWriteBytes(span, out int bytesWritten, isUnsigned: false, isBigEndian: true);
            hash.AppendData(span.Slice(0, bytesWritten));

            // H
            hash.AppendData(exchangeHash);

            // "?"
            span[0] = c;
            hash.AppendData(span.Slice(0, 1));

            // session_id
            hash.AppendData(sessionId);

            return hash.GetHashAndReset();
        }

        private BigInteger DeriveSharedSecret(ECDiffieHellman ecdh, ECDiffieHellmanPublicKey peerPublicKey)
        {
            // TODO: this uses Reflection on the OpenSSL implementation to figure out the shared key.
            // Can we use 'ECDiffieHellman.DeriveKeyFromHash' instead?

            var method = ecdh.GetType().GetMethod("DeriveSecretAgreement", BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { typeof(ECDiffieHellmanPublicKey), typeof(IncrementalHash) }, null);
            if (method != null)
            {
                object? rv = method.Invoke(ecdh, new[] { peerPublicKey, null });
                if (rv is byte[] privateKey)
                {
                    var bigInt = new BigInteger(privateKey, isUnsigned: false, isBigEndian: true);
                    privateKey.AsSpan().Clear();
                    return bigInt;
                }
            }

            throw new NotSupportedException("Cannot determine private key.");
        }
        public void Dispose()
        {}

        private static Sequence CreateEcdhInitMessage(SequencePool sequencePool, ECPoint q_c)
        {
            using var writer = new SequenceWriter(sequencePool);
            writer.WriteByte(MessageNumber.SSH_MSG_KEX_ECDH_INIT);
            writer.WriteECPoint(q_c);
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
            ECPoint q_s = reader.ReadECPoint();
            ReadOnlySequence<byte> exchange_hash_signature = reader.ReadStringAsBytes();
            reader.ReadEnd();
            return (
                public_host_key,
                q_s,
                exchange_hash_signature);
        }
    }
}