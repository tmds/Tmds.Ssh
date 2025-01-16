// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
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

    public override async Task<KeyExchangeOutput> TryExchangeAsync(KeyExchangeContext context, IHostKeyVerification hostKeyVerification, Packet firstPacket, KeyExchangeInput input, ILogger logger, CancellationToken ct)
    {
        var sequencePool = context.SequencePool;
        var connectionInfo = input.ConnectionInfo;

        AsymmetricCipherKeyPair sntrup761KeyPair;
        AsymmetricCipherKeyPair x25519KeyPair;
        using (var randomGenerator = new CryptoApiRandomGenerator())
        {
            var sntrup761KeyPairGenerator = new SNtruPrimeKeyPairGenerator();
            sntrup761KeyPairGenerator.Init(new SNtruPrimeKeyGenerationParameters(new SecureRandom(randomGenerator), _sntruPrimeParameters));
            sntrup761KeyPair = sntrup761KeyPairGenerator.GenerateKeyPair();

            var x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom(randomGenerator)));
            x25519KeyPair = x25519KeyPairGenerator.GenerateKeyPair();
        }

        // Send ECDH_INIT.
        byte[] q_c = ((SNtruPrimePublicKeyParameters)sntrup761KeyPair.Public).GetEncoded();
        int sntrup761PublicKeySize = q_c.Length;
        Array.Resize(ref q_c, sntrup761PublicKeySize + X25519PublicKeyParameters.KeySize);
        Buffer.BlockCopy(((X25519PublicKeyParameters)x25519KeyPair.Public).GetEncoded(), 0, q_c, sntrup761PublicKeySize, X25519PublicKeyParameters.KeySize);
        await context.SendPacketAsync(CreateEcdhInitMessage(sequencePool, q_c), ct).ConfigureAwait(false);

        // Receive ECDH_REPLY.
        using Packet ecdhReplyMsg = await context.ReceivePacketAsync(MessageId.SSH_MSG_KEX_ECDH_REPLY, firstPacket.Move(), ct).ConfigureAwait(false);
        var ecdhReply = ParseEcdhReply(ecdhReplyMsg);

        // Verify received key is valid.
        HostKey hostKey = await VerifyHostKeyAsync(hostKeyVerification, input, ecdhReply.public_host_key, ct).ConfigureAwait(false);

        // Compute shared secret.
        byte[] sharedSecret;
        try
        {
            sharedSecret = DeriveSharedSecret(sntrup761KeyPair.Private, x25519KeyPair.Private, ecdhReply.q_s);
        }
        catch (Exception ex)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Cannot determine shared secret.", connectionInfo, ex);
        }

        // Generate exchange hash.
        byte[] exchangeHash = CalculateExchangeHash(sequencePool, input.ConnectionInfo, input.ClientKexInitMsg, input.ServerKexInitMsg, ecdhReply.public_host_key.Data, q_c, ecdhReply.q_s, sharedSecret, _hashAlgorithmName);

        // Verify the server's signature.
        VerifySignature(hostKey, input.HostKeyAlgorithms, exchangeHash, ecdhReply.exchange_hash_signature, connectionInfo);

        return CalculateKeyExchangeOutput(input, sequencePool, sharedSecret, exchangeHash, _hashAlgorithmName);
    }

    private static byte[] DeriveSharedSecret(AsymmetricKeyParameter sntrup761PrivateKey, AsymmetricKeyParameter x25519PrivateKey, byte[] q_s)
    {
        var sntrup761Extractor = new SNtruPrimeKemExtractor((SNtruPrimePrivateKeyParameters)sntrup761PrivateKey);
        byte[] rawSecretAgreement = sntrup761Extractor.ExtractSecret(q_s[..sntrup761Extractor.EncapsulationLength]);
        int sntrup761SecretLength = rawSecretAgreement.Length;

        var x25519Agreement = new X25519Agreement();
        x25519Agreement.Init(x25519PrivateKey);

        var x25519PublicKey = new X25519PublicKeyParameters(q_s, sntrup761Extractor.EncapsulationLength);
        Array.Resize(ref rawSecretAgreement, sntrup761SecretLength + x25519Agreement.AgreementSize);

        x25519Agreement.CalculateAgreement(x25519PublicKey, rawSecretAgreement, sntrup761SecretLength);

        var sharedSecret = SHA512.HashData(rawSecretAgreement);
        rawSecretAgreement.AsSpan().Clear();
        return sharedSecret;
    }
}
