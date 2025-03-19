// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Buffers;
using System.Buffers.Text;

namespace Tmds.Ssh;

partial class PrivateKeyParser
{
    internal static PrivateKey ParsePrivateKey(ReadOnlyMemory<char> rawKey, Func<string?> passwordPrompt)
        => ParseKey(rawKey, passwordPrompt, parsePrivate: true).PrivateKey!;

    internal static (SshKeyData keyData, bool isEncrypted) ParsePublicKey(ReadOnlyMemory<char> rawKey)
    {
        var result = ParseKey(rawKey, passwordPrompt: delegate { return null; }, parsePrivate: false);
        return (result.PublicKey, result.IsEncrypted);
    }

    private static (SshKeyData PublicKey, bool IsEncrypted, PrivateKey? PrivateKey) ParseKey(ReadOnlyMemory<char> rawKey, Func<string?> passwordPrompt, bool parsePrivate)
    {
        ReadOnlySpan<char> content = rawKey.Span;
        if (!PemEncoding.TryFind(content, out PemFields fields))
        {
            throw new InvalidDataException($"No PEM-encoded data found.");
        }

        byte[] keyData = ArrayPool<byte>.Shared.Rent(fields.DecodedDataLength);
        try
        {
            if (!Convert.TryFromBase64Chars(content[fields.Base64Data], keyData, out int bytesWritten)
                || bytesWritten != fields.DecodedDataLength)
            {
                throw new InvalidDataException($"Invalid Base64 data.");
            }

            ReadOnlySpan<char> keyFormat = content[fields.Label];
            switch (keyFormat)
            {
                case "OPENSSH PRIVATE KEY":
                    return ParseOpenSshKey(keyData.AsMemory(0, bytesWritten), passwordPrompt, parsePrivate);
                default:
                    throw new NotSupportedException($"Unsupported format: '{keyFormat}'.");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(keyData);
        }
    }
}
