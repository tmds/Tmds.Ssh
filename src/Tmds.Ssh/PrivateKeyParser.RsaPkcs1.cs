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
    internal static PrivateKey ParseRsaPkcs1PemKey(
        ReadOnlySpan<byte> keyData,
        Dictionary<string, string> metadata)
    {
        RSA? rsa = RSA.Create();
        try
        {
            if (metadata.TryGetValue("DEK-Info", out var dekInfo))
            {
                throw new NotImplementedException($"PKCS#1 key decryption is not implemented.");
            }

            rsa.ImportRSAPrivateKey(keyData, out int bytesRead);
            if (bytesRead != keyData.Length)
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
}
