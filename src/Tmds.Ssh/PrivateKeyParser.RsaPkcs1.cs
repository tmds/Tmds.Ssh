// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Tmds.Ssh;

partial class PrivateKeyParser
{
    /// <summary>
    /// Parses an RSA PKCS#1 PEM formatted key. This is a legacy format used
    /// by older ssh-keygen and openssl versions for RSA based keys.
    /// </summary>
    internal static bool TryParseRsaPkcs1PemKey(
        ReadOnlySpan<byte> keyData,
        Dictionary<string, string> metadata,
        [NotNullWhen(true)] out PrivateKey? privateKey,
        [NotNullWhen(false)] out Exception? error)
    {
        privateKey = null;
        RSA? rsa = RSA.Create();
        try
        {
            if (metadata.TryGetValue("DEK-Info", out var dekInfo))
            {
                error = new NotImplementedException($"PKCS#1 key decryption is not implemented.");
                return false;
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
}
