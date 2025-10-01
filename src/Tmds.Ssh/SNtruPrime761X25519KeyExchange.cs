// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pqc.Crypto.NtruPrime;
using Org.BouncyCastle.Security;

namespace Tmds.Ssh;

// Key Exchange Method Using Hybrid Streamlined NTRU Prime sntrup761 and X25519
// https://www.ietf.org/archive/id/draft-ietf-sshm-ntruprime-ssh-01.html
sealed class SNtruPrime761X25519KeyExchange : Curve25519KeyExchange
{
    private readonly SNtruPrimeParameters _sntruPrimeParameters = SNtruPrimeParameters.sntrup761;
    private readonly HashAlgorithmName _hashAlgorithmName = HashAlgorithmName.SHA512;

    public override async Task<KeyExchangeOutput> TryExchangeAsync(KeyExchangeContext context, IHostKeyAuthentication hostKeyAuthentication, Packet firstPacket, KeyExchangeInput input, ILogger logger, CancellationToken ct)
    {
        var sequencePool = context.SequencePool;
        var connectionInfo = input.ConnectionInfo;

        // Send ECDH_INIT.
        byte[] q_c = GenerateHybridPublicKey(out AsymmetricCipherKeyPair sntrup761KeyPair, out ECCurve curve, out ECDiffieHellman? ecdh, out AsymmetricCipherKeyPair? x25519KeyPair);
        await context.SendPacketAsync(CreateEcdhInitMessage(sequencePool, q_c), ct).ConfigureAwait(false);

        // Receive ECDH_REPLY.
        using Packet ecdhReplyMsg = await context.ReceivePacketAsync(MessageId.SSH_MSG_KEX_ECDH_REPLY, firstPacket.Move(), ct).ConfigureAwait(false);
        var ecdhReply = ParseEcdhReply(ecdhReplyMsg);

        // Verify received key is valid.
        await VerifyHostKeyAsync(hostKeyAuthentication, input, ecdhReply.public_host_key, ct).ConfigureAwait(false);

        // Compute shared secret.
        byte[] sharedSecret;
        try
        {
            byte[] rawSecretAgreement = DeriveHybridRawSecretAgreement(sntrup761KeyPair, curve, ecdh, x25519KeyPair, ecdhReply.q_s);
            sharedSecret = DeriveSharedSecret(rawSecretAgreement);
        }
        catch (Exception ex)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Cannot determine shared secret.", connectionInfo, ex);
        }

        // Generate exchange hash.
        byte[] exchangeHash = CalculateExchangeHash(sequencePool, input.ConnectionInfo, input.ClientKexInitMsg, input.ServerKexInitMsg, ecdhReply.public_host_key.RawData, q_c, ecdhReply.q_s, sharedSecret, _hashAlgorithmName);

        // Verify the server's signature.
        VerifySignature(connectionInfo.ServerKey, input.HostKeyAlgorithms, exchangeHash, ecdhReply.exchange_hash_signature, connectionInfo);

        return CalculateKeyExchangeOutput(input, sequencePool, sharedSecret, exchangeHash, _hashAlgorithmName);
    }

    private byte[] GenerateHybridPublicKey(out AsymmetricCipherKeyPair sntrup761KeyPair, out ECCurve curve, out ECDiffieHellman? myECDH, out AsymmetricCipherKeyPair? x25519KeyPair)
    {
        using (var randomGenerator = new CryptoApiRandomGenerator())
        {
            var sntrup761KeyPairGenerator = new SNtruPrimeKeyPairGenerator();
            sntrup761KeyPairGenerator.Init(new SNtruPrimeKeyGenerationParameters(new SecureRandom(randomGenerator), _sntruPrimeParameters));
            sntrup761KeyPair = sntrup761KeyPairGenerator.GenerateKeyPair();
        }

        byte[] publicKey = ((SNtruPrimePublicKeyParameters)sntrup761KeyPair.Public).GetEncoded();

        byte[] x25519PublicKey = GeneratePublicKey(out curve, out myECDH, out x25519KeyPair);
        Array.Resize(ref publicKey, publicKey.Length + x25519PublicKey.Length);
        Array.Copy(x25519PublicKey, 0, publicKey, publicKey.Length - x25519PublicKey.Length, x25519PublicKey.Length);

        return publicKey;
    }

    private static byte[] DeriveHybridRawSecretAgreement(AsymmetricCipherKeyPair sntrup761KeyPair, ECCurve curve, ECDiffieHellman? ecdh, AsymmetricCipherKeyPair? x25519KeyPair, byte[] s_reply)
    {
        var sntrup761Extractor = new SNtruPrimeKemExtractor((SNtruPrimePrivateKeyParameters)sntrup761KeyPair.Private);
        byte[] rawSecretAgreement = sntrup761Extractor.ExtractSecret(s_reply[..sntrup761Extractor.EncapsulationLength]);

        byte[] x25519Agreement = DeriveRawSecretAgreement(curve, ecdh, x25519KeyPair, s_reply.AsSpan(sntrup761Extractor.EncapsulationLength));
        Array.Resize(ref rawSecretAgreement, rawSecretAgreement.Length + x25519Agreement.Length);
        Array.Copy(x25519Agreement, 0, rawSecretAgreement, rawSecretAgreement.Length - x25519Agreement.Length, x25519Agreement.Length);

        return rawSecretAgreement;
    }

    private static byte[] DeriveSharedSecret(byte[] rawSecretAgreement)
    {
        byte[] sharedSecret = SHA512.HashData(rawSecretAgreement);
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
    }
}
