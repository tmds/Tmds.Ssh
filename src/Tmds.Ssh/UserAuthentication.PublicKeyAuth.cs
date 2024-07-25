// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Text;

namespace Tmds.Ssh;

partial class UserAuthentication
{
    // https://datatracker.ietf.org/doc/html/rfc4252 - Public Key Authentication Method: "publickey"
    internal sealed class PublicKeyAuth
    {
        public static async Task<bool> TryAuthenticate(PrivateKeyCredential keyCredential, UserAuthContext context, SshConnectionInfo connectionInfo, ILogger logger, CancellationToken ct)
        {
            if (!context.IsAuthenticationAllowed(AlgorithmNames.PublicKey))
            {
                return false;
            }

            string filename = keyCredential.FilePath;
            if (!File.Exists(filename))
            {
                return false;
            }

            if (TryParsePrivateKeyFile(keyCredential.FilePath, keyCredential.Passphrase, out PrivateKey? pk, out Exception? error))
            {
                using (pk)
                {
                    if (pk is RsaPrivateKey rsaKey)
                    {
                        if (rsaKey.KeySize < context.MinimumRSAKeySize)
                        {
                            // TODO: log
                            return false;
                        }
                    }

                    foreach (var keyAlgorithm in pk.Algorithms)
                    {
                        if (!context.PublicKeyAcceptedAlgorithms.Contains(keyAlgorithm))
                        {
                            continue;
                        }

                        logger.AuthenticationMethodPublicKey(keyCredential.FilePath);
                        {
                            using var userAuthMsg = CreatePublicKeyRequestMessage(
                                keyAlgorithm, context.SequencePool, context.UserName, connectionInfo.SessionId!, pk!);
                            await context.SendPacketAsync(userAuthMsg.Move(), ct).ConfigureAwait(false);
                        }

                        bool success = await context.ReceiveAuthIsSuccesfullAsync(ct).ConfigureAwait(false);
                        if (success)
                        {
                            return true;
                        }
                    }
                }
            }
            else
            {
                throw new PrivateKeyLoadException(filename, error);
            }

            return false;
        }

        internal static bool TryParsePrivateKeyFile(string filename, ReadOnlySpan<char> passphrase, [NotNullWhen(true)] out PrivateKey? privateKey, [NotNullWhen(false)] out Exception? error)
        {
            privateKey = null;

            ReadOnlySpan<char> keyFormat;
            ReadOnlySpan<char> keyDataBase64;
            // MAYDO verify file doesn't have permissions for group/other.
            if (!File.Exists(filename))
            {
                error = new FileNotFoundException(filename);
                return false;
            }

            string fileContent;
            try
            {
                fileContent = File.ReadAllText(filename);
            }
            catch (IOException ex)
            {
                error = ex;
                return false;
            }

            int formatStart = fileContent.IndexOf("-----BEGIN");
            if (formatStart == -1)
            {
                error = new FormatException($"No start marker.");
                return false;
            }
            int formatStartEnd = fileContent.IndexOf('\n', formatStart);
            if (formatStartEnd == -1)
            {
                error = new FormatException($"No start marker.");
                return false;
            }

            // While not part of RFC 7468 some tools, like 'ssh-keygen -m PEM',
            // add headers before the base64 data which we need to skip.
            int keyStart = formatStartEnd + 1;
            Dictionary<string, string> metadata = new Dictionary<string, string>();
            while (true)
            {
                int nextNewline = fileContent.IndexOf('\n', keyStart);
                if (nextNewline == -1)
                {
                    error = new FormatException($"No end marker.");
                    return false;
                }
                else if (nextNewline == keyStart)
                {
                    keyStart++;
                    continue;
                }

                int headerColon = fileContent.IndexOf(':', keyStart);
                if (headerColon == -1)
                {
                    break;
                }

                string key = fileContent[keyStart..headerColon];
                metadata[key] = fileContent[(headerColon + 2)..nextNewline];

                keyStart = nextNewline + 1;
            }

            int keyEnd = fileContent.IndexOf("-----END");
            if (keyEnd == -1)
            {
                error = new FormatException($"No end marker.");
                return false;
            }
            keyFormat = fileContent.AsSpan(formatStart, formatStartEnd).Trim();
            keyDataBase64 = fileContent.AsSpan(keyStart, keyEnd - keyStart - 1);

            byte[] keyData;
            try
            {
                keyData = Convert.FromBase64String(keyDataBase64.ToString());
            }
            catch (FormatException)
            {
                error = new FormatException($"Invalid base64 data.");
                return false;
            }

            switch (keyFormat)
            {
                case "-----BEGIN RSA PRIVATE KEY-----":
                    return TryParseRsaPkcs1PemKey(keyData, metadata, passphrase, out privateKey, out error);
                case "-----BEGIN OPENSSH PRIVATE KEY-----":
                    return TryParseOpenSshKey(keyData, passphrase, out privateKey, out error);
                default:
                    error = new NotSupportedException($"Unsupported format: '{keyFormat}'.");
                    return false;
            }
        }

        private static bool TryParseRsaPkcs1PemKey(
            ReadOnlySpan<byte> keyData,
            Dictionary<string, string> metadata,
            ReadOnlySpan<char> passphrase,
            [NotNullWhen(true)] out PrivateKey? privateKey,
            [NotNullWhen(false)] out Exception? error)
        {
            privateKey = null;
            RSA? rsa = RSA.Create();
            try
            {
                if (metadata.TryGetValue("DEK-Info", out var dekInfo))
                {
                    int dekIdx = dekInfo.IndexOf(',');
                    if (dekIdx == -1)
                    {
                        error = new FormatException($"Failed to decrypt PKCS#1 RSA key, unknown DEK-Info '{dekInfo}'.");
                        return false;
                    }

                    string algoName = dekInfo.Substring(0, dekIdx);
                    byte[] iv = Convert.FromHexString(dekInfo.Substring(dekIdx + 1));

                    int keySize;
                    switch (algoName)
                    {
                        case "AES-128-CBC":
                            keySize = 16;
                            break;
                        case "AES-192-CBC":
                            keySize = 24;
                            break;
                        case "AES-256-CBC":
                            keySize = 32;
                            break;
                        default:
                            error = new NotSupportedException($"PKCS#1 RSA encryption algo {algoName} not supported.");
                            return false;
                    }

                    byte[] passphraseBytes = new byte[Encoding.UTF8.GetByteCount(passphrase)];
                    Encoding.UTF8.GetBytes(passphrase, passphraseBytes);
                    byte[] key = Pbkdf1.DeriveKey(HashAlgorithmName.MD5, passphraseBytes, iv.AsSpan(0, 8), 1, keySize);
                    keyData = AesDecrypter.DecryptCbc(key, iv, keyData, PaddingMode.PKCS7);
                }

                rsa.ImportRSAPrivateKey(keyData, out int bytesRead);
                if (bytesRead != keyData.Length)
                {
                    rsa.Dispose();
                    error = new FormatException($"There is additional data after the RSA key.");
                    return false;
                }
                privateKey = new RsaPrivateKey(rsa);
                error = null;
                return true;
            }
            catch (Exception ex)
            {
                rsa?.Dispose();
                error = new FormatException($"The data can not be parsed into an RSA key.", ex);
                return false;
            }
        }

        private static bool TryParseOpenSshKey(byte[] keyData, ReadOnlySpan<char> passphrase, out PrivateKey? privateKey, out Exception? error)
        {
            privateKey = null;

            // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
            /*
                byte[]	AUTH_MAGIC
                string	ciphername
                string	kdfname
                string	kdfoptions
                uint32	number of keys N
                string	publickey1
                string	publickey2
                ...
                string	publickeyN
                string	encrypted, padded list of private keys
            */
            ReadOnlySpan<byte> AUTH_MAGIC = "openssh-key-v1\0"u8;
            if (!keyData.AsSpan().StartsWith(AUTH_MAGIC))
            {
                error = new FormatException($"Unknown OpenSSH key format.");
                return false;
            }
            ReadOnlySequence<byte> ros = new ReadOnlySequence<byte>(keyData);
            ros = ros.Slice(AUTH_MAGIC.Length);
            var reader = new SequenceReader(ros);
            Name cipherName = reader.ReadName();
            Name kdfName = reader.ReadName();
            ReadOnlySequence<byte> kdfOptions = reader.ReadStringAsBytes();
            uint nrOfKeys = reader.ReadUInt32();
            if (nrOfKeys != 1)
            {
                error = new FormatException($"The data contains multiple keys.");
                return false; // Multiple keys are not supported.
            }
            reader.SkipString(); // skip the public key
            ReadOnlySequence<byte> privateKeyList;
            if (cipherName == AlgorithmNames.None)
            {
                privateKeyList = reader.ReadStringAsBytes();
            }
            else
            {
                if (!TryDecryptOpenSshPrivateKey(reader, cipherName, kdfName, kdfOptions, passphrase, out var decryptedKey, out error))
                {
                    return false;
                }
                privateKeyList = new ReadOnlySequence<byte>(decryptedKey);
            }

            reader = new SequenceReader(privateKeyList);
            /*
                uint32	checkint
                uint32	checkint
                byte[]	privatekey1
                string	comment1
                byte[]	privatekey2
                string	comment2
                ...
                byte[]	privatekeyN
                string	commentN
                byte	1
                byte	2
                byte	3
                ...
                byte	padlen % 255
            */
            uint checkInt1 = reader.ReadUInt32();
            uint checkint2 = reader.ReadUInt32();
            if (checkInt1 != checkint2)
            {
                error = new FormatException($"The checkints mismatch. The key is invalid or the passphrase is wrong.");
                return false;
            }

            Name keyType = reader.ReadName();
            if (keyType == AlgorithmNames.SshRsa)
            {
                return TryParseOpenSshRsaKey(reader, out privateKey, out error);
            }
            if (keyType.ToString().StartsWith("ecdsa-sha2-"))
            {
                return TryParseOpenSshEcdsaKey(keyType, reader, out privateKey, out error);
            }
            else
            {
                error = new NotSupportedException($"The key type is unsupported: '{keyType}'.");
                return false;
            }
        }

        private static bool TryParseOpenSshRsaKey(SequenceReader reader, [NotNullWhen(true)] out PrivateKey? privateKey, [NotNullWhen(false)] out Exception? error)
        {
            privateKey = null;

            byte[] modulus = reader.ReadMPIntAsByteArray(isUnsigned: true);
            byte[] exponent = reader.ReadMPIntAsByteArray(isUnsigned: true);
            BigInteger d = reader.ReadMPInt();
            byte[] inverseQ = reader.ReadMPIntAsByteArray(isUnsigned: true);
            BigInteger p = reader.ReadMPInt();
            BigInteger q = reader.ReadMPInt();

            BigInteger dp = d % (p - BigInteger.One);
            BigInteger dq = d % (q - BigInteger.One);

            RSAParameters parameters = new()
            {
                Modulus = modulus,
                Exponent = exponent,
                D = d.ToByteArray(isUnsigned: true, isBigEndian: true),
                InverseQ = inverseQ,
                P = p.ToByteArray(isUnsigned: true, isBigEndian: true),
                Q = q.ToByteArray(isUnsigned: true, isBigEndian: true),
                DP = dp.ToByteArray(isUnsigned: true, isBigEndian: true),
                DQ = dq.ToByteArray(isUnsigned: true, isBigEndian: true)
            };
            RSA rsa = RSA.Create();
            try
            {
                rsa.ImportParameters(parameters);
                privateKey = new RsaPrivateKey(rsa);
                error = null;
                return true;
            }
            catch (Exception ex)
            {
                error = new FormatException($"The data can not be parsed into an RSA key.", ex);
                rsa.Dispose();
                return false;
            }
        }

        private static bool TryParseOpenSshEcdsaKey(Name keyIdentifier, SequenceReader reader, [NotNullWhen(true)] out PrivateKey? privateKey, [NotNullWhen(false)] out Exception? error)
        {
            privateKey = null;

            Name curveName = reader.ReadName();

            HashAlgorithmName allowedHashAlgo;
            ECCurve curve;
            if (curveName == AlgorithmNames.Nistp256)
            {
                allowedHashAlgo = HashAlgorithmName.SHA256;
                curve = ECCurve.NamedCurves.nistP256;
            }
            else if (curveName == AlgorithmNames.Nistp384)
            {
                allowedHashAlgo = HashAlgorithmName.SHA384;
                curve = ECCurve.NamedCurves.nistP384;
            }
            else if (curveName == AlgorithmNames.Nistp521)
            {
                allowedHashAlgo = HashAlgorithmName.SHA512;
                curve = ECCurve.NamedCurves.nistP521;
            }
            else
            {
                error = new NotSupportedException($"ECDSA curve '{curveName}' is unsupported.");
                return false;
            }

            ECPoint q = reader.ReadStringAsECPoint();
            byte[] d = reader.ReadMPIntAsByteArray(isUnsigned: true, minLength: q.X!.Length);

            ECDsa ecdsa = ECDsa.Create();
            try
            {
                ECParameters parameters = new()
                {
                    Curve = curve,
                    Q = q,
                    D = d
                };

                ecdsa.ImportParameters(parameters);
                privateKey = new ECDsaPrivateKey(ecdsa, keyIdentifier, curveName, allowedHashAlgo);
                error = null;
                return true;
            }
            catch (Exception ex)
            {
                error = new FormatException($"The data can not be parsed into an ECDSA key.", ex);
                ecdsa.Dispose();
                return false;
            }
        }

        private static bool TryDecryptOpenSshPrivateKey(
            SequenceReader reader,
            Name cipher,
            Name kdf,
            ReadOnlySequence<byte> kdfOptions,
            ReadOnlySpan<char> passphrase,
            [NotNullWhen(true)] out byte[]? privateKey,
            [NotNullWhen(false)] out Exception? error)
        {
            privateKey = null;

            if (kdf != AlgorithmNames.Bcrypt)
            {
                error = new NotSupportedException($"Unsupported KDF: '{kdf}'.");
                return false; // kdfName not supported.
            }

            /*
            	string salt
	            uint32 rounds
            */
            var kdfReader = new SequenceReader(kdfOptions);
            ReadOnlySequence<byte> kdfSalt = kdfReader.ReadStringAsBytes();
            uint rounds = kdfReader.ReadUInt32();

            EncryptionAlgorithm encAlgo;
            try
            {
                encAlgo = EncryptionAlgorithm.Find(cipher);

                byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase.ToArray());
                byte[] derivedKey = new byte[encAlgo.KeyLength + encAlgo.IVLength];

                new BCrypt().Pbkdf(
                    passphraseBytes,
                    kdfSalt.IsSingleSegment ? kdfSalt.FirstSpan : kdfSalt.ToArray(),
                    (int)rounds,
                    derivedKey);

                ReadOnlySequence<byte> encryptedKey = reader.ReadStringAsBytes();
                ReadOnlySequence<byte> tag = default;
                if (encAlgo.IsAuthenticated && encAlgo.TagLength > 0)
                {
                    if (!reader.TryRead(encAlgo.TagLength, out tag))
                    {
                        error = new FormatException($"Failed to read {cipher} encryption tag for OpenSSH key.");
                        return false;
                    }
                }

                privateKey = encAlgo.DecryptData(
                    derivedKey.AsSpan(0, encAlgo.KeyLength),
                    derivedKey.AsSpan(encAlgo.KeyLength, encAlgo.IVLength),
                    encryptedKey.IsSingleSegment ? encryptedKey.FirstSpan : encryptedKey.ToArray(),
                    tag.IsSingleSegment ? tag.FirstSpan : tag.ToArray());
                error = null;
                return true;
            }
            catch (Exception ex)
            {
                error = new FormatException($"Failed to decrypt OpenSSH key with cipher {cipher}.", ex);
                return false;
            }
        }

        private static Packet CreatePublicKeyRequestMessage(Name algorithm, SequencePool sequencePool, string userName, byte[] sessionId, PrivateKey privateKey)
        {
            /*
                byte      SSH_MSG_USERAUTH_REQUEST
                string    user name
                string    service name
                string    "publickey"
                boolean   TRUE
                string    public key algorithm name
                string    public key to be used for authentication
                string    signature
             */
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
            writer.WriteString(userName);
            writer.WriteString("ssh-connection");
            writer.WriteString("publickey");
            writer.WriteBoolean(true);
            writer.WriteString(algorithm);
            privateKey.AppendPublicKey(ref writer);
            {
                /*
                    string    session identifier
                    byte      SSH_MSG_USERAUTH_REQUEST
                    string    user name
                    string    service name
                    string    "publickey"
                    boolean   TRUE
                    string    public key algorithm name
                    string    public key to be used for authentication
                 */
                using var signatureData = sequencePool.RentSequence();
                var signatureWriter = new SequenceWriter(signatureData);
                signatureWriter.WriteString(sessionId);
                signatureWriter.WriteMessageId(MessageId.SSH_MSG_USERAUTH_REQUEST);
                signatureWriter.WriteString(userName);
                signatureWriter.WriteString("ssh-connection");
                signatureWriter.WriteString("publickey");
                signatureWriter.WriteBoolean(true);
                signatureWriter.WriteString(algorithm);
                privateKey.AppendPublicKey(ref signatureWriter);
                privateKey.AppendSignature(algorithm, ref writer, signatureData.AsReadOnlySequence());
            }

            return packet.Move();
        }
    }
}