// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Numerics;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

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

        public async Task<KeyExchangeOutput> TryExchangeAsync(SshConnection connection, SshClientSettings settings, KeyExchangeInput input, ILogger logger, CancellationToken ct)
        {
            var sequencePool = connection.SequencePool;
            var connectionInfo = input.ConnectionInfo;
            using ECDiffieHellman ecdh = ECDiffieHellman.Create(_ecCurve);

            // Send ECDH_INIT.
            using ECDiffieHellmanPublicKey myPublicKey = ecdh.PublicKey;
            ECPoint q_c = myPublicKey.ExportParameters().Q;
            {
                using var ecdhInitMsg = CreateEcdhInitMessage(sequencePool, q_c);
                await connection.SendPacketAsync(ecdhInitMsg, ct);
            }

            // Receive ECDH_REPLY.
            Packet exchangeInitMsg = input.ExchangeInitMsg;
            using Packet exchangeInitMsgDispose =
                exchangeInitMsg.IsEmpty ? (exchangeInitMsg = await connection.ReceivePacketAsync(ct)) : default(Packet);
            var ecdhReply = ParceEcdhReply(exchangeInitMsg, input.HostKeyAlgorithms);

            // Verify received key is valid.
            connectionInfo.SshKey = ecdhReply.public_host_key;
            var verificationResult = await settings.HostKeyVerification.VerifyAsync(connectionInfo, ct);
            if (verificationResult != HostKeyVerificationResult.Trusted)
            {
                throw new KeyExchangeFailedException("The host key is not trusted.");
            }

            var publicHostKey = PublicKey.CreateFromSshKey(ecdhReply.public_host_key);
            // Compute shared secret.
            BigInteger sharedSecret;
            try
            {
                sharedSecret = DeriveSharedSecret(ecdh, ecdhReply.q_s.X, ecdhReply.q_s.Y);
            }
            catch (Exception ex)
            {
                throw new KeyExchangeFailedException("Cannot determine shared secret.", ex);
            }

            // Generate exchange hash.
            byte[] exchangeHash = CalculateExchangeHash(sequencePool, input.ConnectionInfo, input.ClientKexInitMsg, input.ServerKexInitMsg, ecdhReply.public_host_key.Key, q_c, ecdhReply.q_s, sharedSecret);

            // Verify the server's signature.
            if (!publicHostKey.VerifySignature(exchangeHash, ecdhReply.exchange_hash_signature))
            {
                throw new KeyExchangeFailedException("Signature does not match host key.");
            }

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

        private byte[] CalculateExchangeHash(SequencePool sequencePool, SshConnectionInfo connectionInfo, Packet clientKexInitMsg, Packet serverKexInitMsg, byte[] public_host_key, ECPoint q_c, ECPoint q_s, BigInteger sharedSecret)
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

        private BigInteger DeriveSharedSecret(ECDiffieHellman ecdh, byte[] q_x, byte[] q_y)
        {
            var basicAgreement = new ECDHCBasicAgreement();
            ECParameters privParameters = ecdh.ExportParameters(includePrivateParameters: true);
            X9ECParameters curve = NistNamedCurves.GetByOid(new DerObjectIdentifier(privParameters.Curve.Oid.Value));
            ECDomainParameters ecParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            Org.BouncyCastle.Math.EC.ECPoint peer_q = ecParams.Curve.CreatePoint(ToBCBigInteger(q_x), ToBCBigInteger(q_y));
            var bcPrivateParams = new ECPrivateKeyParameters(
                algorithm: "ECDHC",
                d: ToBCBigInteger(privParameters.D),
                parameters: ecParams);
            basicAgreement.Init(bcPrivateParams);
            var bcPeerParameters = new ECPublicKeyParameters(
                algorithm: "ECDHC",
                q: peer_q,
                parameters: ecParams);
            var secret = basicAgreement.CalculateAgreement(bcPeerParameters);
            return secret.ToByteArrayUnsigned().ToBigInteger();

            static Org.BouncyCastle.Math.BigInteger ToBCBigInteger(byte[] span)
            {
                return new Org.BouncyCastle.Math.BigInteger(1, span);
            }
        }

        public void Dispose()
        { }

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
            ParceEcdhReply(Packet packet, IReadOnlyList<Name> allowedKeyTypes)
        {
            var reader = packet.GetReader();
            reader.ReadMessageId(MessageId.SSH_MSG_KEX_ECDH_REPLY);
            SshKey public_host_key = reader.ReadSshKey(allowedKeyTypes);
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