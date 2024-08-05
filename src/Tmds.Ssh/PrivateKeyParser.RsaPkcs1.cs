// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
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
        ReadOnlySpan<byte> passphrase,
        [NotNullWhen(true)] out PrivateKey? privateKey,
        [NotNullWhen(false)] out Exception? error)
    {
        privateKey = null;
        RSA? rsa = RSA.Create();
        try
        {
            if (metadata.TryGetValue("DEK-Info", out var dekInfo))
            {
                if (passphrase.Length == 0)
                {
                    error = new FormatException($"The key is encrypted but no passphrase was provided.");
                    return false;
                }

                int dekIdx = dekInfo.IndexOf(',');
                if (dekIdx == -1)
                {
                    error = new FormatException($"Failed to decrypt PKCS#1 RSA key, unknown DEK-Info '{dekInfo}'.");
                    return false;
                }

                Name algoName = new Name(dekInfo.Substring(0, dekIdx));
                byte[] iv = Convert.FromHexString(dekInfo.AsSpan(dekIdx + 1));

                int keySize;
                if (algoName == AlgorithmNames.Pkcs1Aes128Cbc)
                {
                    keySize = 16;
                }
                else if (algoName == AlgorithmNames.Pkcs1Aes192Cbc)
                {
                    keySize = 24;
                }
                else if (algoName == AlgorithmNames.Pkcs1Aes256Cbc)
                {
                    keySize = 32;
                }
                else
                {
                    error = new NotSupportedException($"PKCS#1 RSA encryption algo {algoName} not supported.");
                    return false;
                }

                // Yes this is an MD5 hash and 1 round, PKCS#1 is old and uses
                // some weak cryptography components.
                byte[] key = Pbkdf1(HashAlgorithmName.MD5, passphrase, iv.AsSpan(0, 8), 1, keySize);
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

    /// <summary>
    /// Modified version of PBKDF1 to derive a key for a PKCS#1 encrypted cipher.
    /// The modifications allow for deriving a key larger than the used hash length.
    /// </summary>
    private static byte[] Pbkdf1(
        HashAlgorithmName hashName,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> salt,
        int rounds,
        int keySize)
    {
        using var hash = IncrementalHash.CreateHash(hashName);

        // Our initial output needs to be a multiple of the hash length.
        // The desired size is trimmed on return.
        int totalSize = (keySize + hash.HashLengthInBytes - 1) & ~(hash.HashLengthInBytes - 1);
        byte[] output = new byte[totalSize];

        // We may need to derive a key that is larger than the hash length.
        // This is a deviation from the PBKDF1 spec but is needed for PKCS#1
        // cipher keys. We repeat the process for the same amount of rounds
        // but start with the existing output data.
        int outWritten = 0;
        while (outWritten < output.Length)
        {
            ReadOnlySpan<byte> hashData = data;
            ReadOnlySpan<byte> saltData = salt;

            // First round should include the existing output data if any.
            if (outWritten > 0)
            {
                hash.AppendData(output.AsSpan(0, outWritten));
            }

            for (int i = 0; i < rounds; i++)
            {
                hash.AppendData(hashData);
                if (saltData.Length > 0)
                {
                    hash.AppendData(saltData);
                }

                hash.GetHashAndReset(output.AsSpan(outWritten));

                // Next rounds should use the hash as the data and no salt.
                hashData = output.AsSpan(outWritten, hash.HashLengthInBytes);
                saltData = Span<byte>.Empty;
            }

            outWritten += hash.HashLengthInBytes;
        }

        return output.AsSpan(0, keySize).ToArray();
    }
}
