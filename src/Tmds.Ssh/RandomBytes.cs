// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

static class RandomBytes
{
    public static void Fill(Span<byte> data)
    {
        RandomNumberGenerator.Fill(data);
    }
}
