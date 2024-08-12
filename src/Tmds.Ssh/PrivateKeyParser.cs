// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;

namespace Tmds.Ssh;

partial class PrivateKeyParser
{
    internal static bool TryParsePrivateKeyFile(string filename, Func<string?> passwordPrompt, [NotNullWhen(true)] out PrivateKey? privateKey, [NotNullWhen(false)] out Exception? error)
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

        // While not part of RFC 7468, PKCS#1 RSA keys have extra metadata
        // after the begin marker and before the base64 data. We need to
        // parse that information for decryption and so it doesn't break
        // our validator.
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
                return TryParseRsaPkcs1PemKey(keyData, metadata, out privateKey, out error);
            case "-----BEGIN OPENSSH PRIVATE KEY-----":
                return TryParseOpenSshKey(keyData, passwordPrompt, out privateKey, out error);
            default:
                error = new NotSupportedException($"Unsupported format: '{keyFormat}'.");
                return false;
        }
    }
}
