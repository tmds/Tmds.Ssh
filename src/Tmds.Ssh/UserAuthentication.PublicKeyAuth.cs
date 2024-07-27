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

namespace Tmds.Ssh;

partial class UserAuthentication
{
    // https://datatracker.ietf.org/doc/html/rfc4252 - Public Key Authentication Method: "publickey"
    sealed class PublicKeyAuth
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

            if (TryParsePrivateKeyFile(keyCredential.FilePath, out PrivateKey? pk, out Exception? error))
            {
                using (pk)
                {
                    foreach (var keyAlgorithm in pk.Algorithms)
                    {
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

        internal static bool TryParsePrivateKeyFile(string filename, [NotNullWhen(true)] out PrivateKey? privateKey, [NotNullWhen(false)] out Exception? error)
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
            int keyStart = fileContent.IndexOf('\n', formatStart);
            if (keyStart == -1)
            {
                error = new FormatException($"No start marker.");
                return false;
            }
            keyStart++;
            int keyEnd = fileContent.IndexOf("-----END");
            if (formatStart == -1)
            {
                error = new FormatException($"No end marker.");
                return false;
            }
            keyFormat = fileContent.AsSpan(formatStart, keyStart - formatStart - 1).Trim();
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
                    return TryParseRsaPemKey(keyData, out privateKey, out error);
                case "-----BEGIN OPENSSH PRIVATE KEY-----":
                    return TryParseOpenSshKey(keyData, out privateKey, out error);
                default:
                    error = new NotSupportedException($"Unsupported format: '{keyFormat}'.");
                    return false;
            }
        }

        private static bool TryParseRsaPemKey(byte[] keyData, out PrivateKey? privateKey, out Exception? error)
        {
            privateKey = null;
            RSA? rsa = RSA.Create();
            try
            {
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

        private static bool TryParseOpenSshKey(byte[] keyData, out PrivateKey? privateKey, out Exception? error)
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
            if (cipherName != AlgorithmNames.None)
            {
                error = new NotSupportedException($"Unsupported cipher: '{cipherName}'.");
                return false; // cipherName not supported.
            }
            reader.SkipString(); // kfdname
            reader.SkipString(); // kdfoptions
            uint nrOfKeys = reader.ReadUInt32();
            if (nrOfKeys != 1)
            {
                error = new FormatException($"The data contains multiple keys.");
                return false; // Multiple keys are not supported.
            }
            reader.SkipString(); // skip the public key
            ReadOnlySequence<byte> privateKeyList = reader.ReadStringAsBytes();
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

            BigInteger modulus = reader.ReadMPInt();
            BigInteger exponent = reader.ReadMPInt();
            BigInteger d = reader.ReadMPInt();
            BigInteger inverseQ = reader.ReadMPInt();
            BigInteger p = reader.ReadMPInt();
            BigInteger q = reader.ReadMPInt();

            BigInteger dp = d % (p - BigInteger.One);
            BigInteger dq = d % (q - BigInteger.One);

            RSAParameters parameters = new()
            {
                Modulus = modulus.ToByteArray(isUnsigned: true, isBigEndian: true),
                Exponent = exponent.ToByteArray(isUnsigned: true, isBigEndian: true),
                D = d.ToByteArray(isUnsigned: true, isBigEndian: true),
                InverseQ = inverseQ.ToByteArray(isUnsigned: true, isBigEndian: true),
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
                error = new FormatException($"ECDSA curve '{curveName}' is unsupported.");
                return false;
            }

            ECPoint q = reader.ReadStringAsECPoint();
            BigInteger dInt = reader.ReadMPInt();
            byte[] d = dInt.ToByteArray(isUnsigned: false, isBigEndian: true);

            ECDsa ecdsa = ECDsa.Create();
            try
            {
                int dRequiredLength = q.X!.Length;
                if (d.Length != dRequiredLength)
                {
                    // ECParameters.D's length needs to match the curve point
                    // coordinates length. We need to remove the leading 0 byte
                    // for the sign if it's there and left pad with 0 if the
                    // length is not enough.
                    byte[] tempD = new byte[dRequiredLength];
                    if (d.Length < dRequiredLength)
                    {
                        d.AsSpan().CopyTo(tempD.AsSpan(dRequiredLength - d.Length));
                    }
                    else
                    {
                        d.AsSpan()[(d.Length - dRequiredLength)..].CopyTo(tempD);
                    }
                    d = tempD;
                }

                ECParameters parameters = new()
                {
                    Curve = curve,
                    D = d,
                    Q = q,
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