// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Security.Cryptography;

namespace Tmds.Ssh;

static class ChaCha20Decrypter
{
    public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.chacha20poly1305
        Span<byte> nonce = stackalloc byte[12];
        Span<byte> tag = stackalloc byte[16];
        tag[0] = 1;  // K_2 sets the counter to 1
        byte[] decData = new byte[data.Length];

        using var chacha = new ChaCha20Poly1305(key);
        chacha.Encrypt(nonce, data, decData, tag);

        return decData;
    }
}
