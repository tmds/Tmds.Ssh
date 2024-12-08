namespace Tmds.Ssh
{
    using System;
    using System.Formats.Asn1;
    using System.Numerics;
    using System.Security.Cryptography;
    using System.Text;
    using Org.BouncyCastle.Asn1.EdEC;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Math.EC.Rfc8032;
    using Org.BouncyCastle.Pkcs;

    partial class PrivateKeyParser
    {
        internal static PrivateKey ParsePkcs8Key(byte[] keyData)
        {
            var privateKeyInfo = PrivateKeyInfo.GetInstance(keyData);
            return ParsePkcs8Key(privateKeyInfo);
        }

        internal static PrivateKey ParsePkcs8Key(byte[] keyData, Func<string?> passwordPrompt)
        {
            var encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.GetInstance(keyData);
            string? password = passwordPrompt();
            if (password is null)
            {
                throw new FormatException("Key was encrypted but no password was provided.");
            }

            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password.ToCharArray(), encryptedPrivateKeyInfo);
            return ParsePkcs8Key(privateKeyInfo);
        }

        private static PrivateKey ParsePkcs8Key(PrivateKeyInfo privateKeyInfo)
        {
            var algorithmOid = privateKeyInfo.PrivateKeyAlgorithm.Algorithm;
            var privateKey = privateKeyInfo.PrivateKey.GetOctets();
            if (algorithmOid.Equals(PkcsObjectIdentifiers.RsaEncryption))
            {
                return ParsePkcs8RsaKey(privateKey);
            }

            if (algorithmOid.Equals(X9ObjectIdentifiers.IdECPublicKey))
            {
                var parameters = privateKeyInfo.PrivateKeyAlgorithm.Parameters.GetDerEncoded();
                return ParsePkcs8EcdsaKey(parameters, privateKey);
            }

            if (algorithmOid.Equals(EdECObjectIdentifiers.id_Ed25519))
            {
                return ParsePkcs8Ed25519Key(privateKey);
            }

            throw new NotSupportedException($"Private key algorithm '{algorithmOid}' is not supported.");
        }

        private static PrivateKey ParsePkcs8RsaKey(byte[] privateKey)
        {
            RSA? rsa = RSA.Create();
            try
            {
                rsa.ImportRSAPrivateKey(privateKey, out int bytesRead);
                if (bytesRead != privateKey.Length)
                {
                    rsa.Dispose();
                    throw new FormatException($"There is additional data after the RSA key.");
                }
                return new RsaPrivateKey(rsa);
            }
            catch (Exception ex)
            {
                rsa?.Dispose();
                throw new FormatException($"The data can not be parsed into an RSA key.", ex);
            }
        }

        private static PrivateKey ParsePkcs8EcdsaKey(byte[] parameters, byte[] privateKey)
        {
            const string ECDSA_P256_OID_VALUE = "1.2.840.10045.3.1.7"; // Also called nistP256 or secP256r1
            const string ECDSA_P384_OID_VALUE = "1.3.132.0.34"; // Also called nistP384 or secP384r1
            const string ECDSA_P521_OID_VALUE = "1.3.132.0.35"; // Also called nistP521 or secP521r1

            var parametersReader = new AsnReader(parameters, AsnEncodingRules.DER);
            var curveOid = parametersReader.ReadObjectIdentifier();
            parametersReader.ThrowIfNotEmpty();

            ECCurve curve;
            Name algorithm;
            Name curveName;
            HashAlgorithmName hashAlgorithm;
            if (curveOid == ECDSA_P256_OID_VALUE)
            {
                (curve, algorithm, curveName, hashAlgorithm) =
                (ECCurve.NamedCurves.nistP256, AlgorithmNames.EcdsaSha2Nistp256, AlgorithmNames.Nistp256, HashAlgorithmName.SHA256);
            }
            else if (curveOid == ECDSA_P384_OID_VALUE)
            {
                (curve, algorithm, curveName, hashAlgorithm) =
                (ECCurve.NamedCurves.nistP384, AlgorithmNames.EcdsaSha2Nistp384, AlgorithmNames.Nistp384, HashAlgorithmName.SHA384);
            }
            else if (curveOid == ECDSA_P521_OID_VALUE)
            {
                (curve, algorithm, curveName, hashAlgorithm) =
                (ECCurve.NamedCurves.nistP521, AlgorithmNames.EcdsaSha2Nistp521, AlgorithmNames.Nistp521, HashAlgorithmName.SHA512);
            }
            else
            {
                throw new NotSupportedException($"ECDSA curve oid '{curveOid}' is unsupported.");
            }

            var privateKeyReader = new AsnReader(privateKey, AsnEncodingRules.DER);
            var sequenceReader = privateKeyReader.ReadSequence();
            privateKeyReader.ThrowIfNotEmpty();

            var version = sequenceReader.ReadInteger();
            if (version != BigInteger.One)
            {
                ThrowHelper.ThrowNotSupportedException($"EC version '{version}' is not supported.");
            }

            var d = sequenceReader.ReadOctetString();

            var publicKeyReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
            ReadOnlySpan<byte> publickey = publicKeyReader.ReadBitString(out _);
            publicKeyReader.ThrowIfNotEmpty();

            sequenceReader.ThrowIfNotEmpty();

            byte firstByte = publickey[0];
            if (firstByte != 0x04) // Check uncompressed.
            {
                ThrowHelper.ThrowNotSupportedException("Reading compressed ECPoints is not supported.");
            }

            if ((publickey.Length - 1) % 2 != 0)
            {
                ThrowHelper.ThrowProtocolECPointInvalidLength();
            }

            var cord_size = (publickey.Length - 1) / 2;

            ECDsa ecdsa = ECDsa.Create();
            try
            {
                ECParameters ecParameters = new()
                {
                    Curve = curve,
                    Q = new ECPoint
                    {
                        X = publickey[1..(cord_size + 1)].ToArray(),
                        Y = publickey[(cord_size + 1)..].ToArray(),
                    },
                    D = d
                };

                ecdsa.ImportParameters(ecParameters);
                return new ECDsaPrivateKey(ecdsa, algorithm, curveName, hashAlgorithm);
            }
            catch (Exception ex)
            {
                ecdsa.Dispose();
                throw new FormatException($"The data can not be parsed into an ECDSA key.", ex);
            }
        }

        private static PrivateKey ParsePkcs8Ed25519Key(byte[] privateKey)
        {
            try
            {
                var publicKey = new byte[Ed25519.PublicKeySize];
                Ed25519.GeneratePublicKey(privateKey, 0, publicKey, 0);

                return new Ed25519PrivateKey(privateKey, publicKey);
            }
            catch (Exception ex)
            {
                throw new FormatException($"The data can not be parsed into an ED25519 key.", ex);
            }
        }
    }
}
