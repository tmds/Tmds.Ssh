// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

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

        internal static bool TryParsePrivateKeyFile(string filename, ReadOnlySpan<byte> passphrase, [NotNullWhen(true)] out PrivateKey? privateKey, [NotNullWhen(false)] out Exception? error)
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
                    return PrivateKeyCredential.TryParseRsaPkcs1PemKey(keyData, metadata, passphrase, out privateKey, out error);
                case "-----BEGIN OPENSSH PRIVATE KEY-----":
                    return PrivateKeyCredential.TryParseOpenSshKey(keyData, passphrase, out privateKey, out error);
                default:
                    error = new NotSupportedException($"Unsupported format: '{keyFormat}'.");
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