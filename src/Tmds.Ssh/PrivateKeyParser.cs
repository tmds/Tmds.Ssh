// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics.CodeAnalysis;

namespace Tmds.Ssh;

partial class PrivateKeyParser
{
    internal static PrivateKey ParsePrivateKey(ReadOnlyMemory<char> rawKey, Func<string?> passwordPrompt)
    {
        ReadOnlySpan<char> content = rawKey.Span;

        int formatStart = content.IndexOf("-----BEGIN");
        if (formatStart == -1)
        {
            throw new FormatException($"No start marker.");
        }
        int formatStartEnd = content.Slice(formatStart).IndexOf('\n');
        if (formatStartEnd == -1)
        {
            throw new FormatException($"No start marker.");
        }

        // While not part of RFC 7468, PKCS#1 RSA keys have extra metadata
        // after the begin marker and before the base64 data. We need to
        // parse that information for decryption and so it doesn't break
        // our validator.
        int keyStart = formatStartEnd + 1;
        Dictionary<string, string> metadata = new Dictionary<string, string>();
        while (true)
        {
            int nextNewline = content.Slice(keyStart).IndexOf('\n');
            if (nextNewline == -1)
            {
                throw new FormatException($"No end marker.");
            }
            else if (nextNewline == keyStart)
            {
                keyStart++;
                continue;
            }

            int headerColon = content.Slice(keyStart).IndexOf(':');
            if (headerColon == -1)
            {
                break;
            }

            string key = rawKey[keyStart..headerColon].ToString();
            metadata[key] = rawKey[(headerColon + 2)..nextNewline].ToString();

            keyStart = nextNewline + 1;
        }

        int keyEnd = content.IndexOf("-----END");
        if (keyEnd == -1)
        {
            throw new FormatException($"No end marker.");
        }
        ReadOnlySpan<char> keyFormat = content.Slice(formatStart, formatStartEnd).Trim();
        ReadOnlySpan<char> keyDataBase64 = content.Slice(keyStart, keyEnd - keyStart - 1);

        byte[] keyData;
        try
        {
            keyData = Convert.FromBase64String(keyDataBase64.ToString());
        }
        catch (FormatException)
        {
            throw new FormatException($"Invalid base64 data.");
        }

        switch (keyFormat)
        {
            case "-----BEGIN RSA PRIVATE KEY-----":
                return ParseRsaPkcs1PemKey(keyData, metadata);
            case "-----BEGIN OPENSSH PRIVATE KEY-----":
                return ParseOpenSshKey(keyData, passwordPrompt);
            case "-----BEGIN PRIVATE KEY-----":
                return ParsePkcs8Key(keyData);
            case "-----BEGIN ENCRYPTED PRIVATE KEY-----":
                return ParsePkcs8Key(keyData, passwordPrompt);
            default:
                throw new NotSupportedException($"Unsupported format: '{keyFormat}'.");
        }
    }
}
