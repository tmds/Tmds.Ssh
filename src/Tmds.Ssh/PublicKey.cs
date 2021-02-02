// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    public sealed class PublicKey
    {
        internal PublicKey(byte[] hash)
        {
            Hash = hash;
        }

        public Memory<byte> Hash { get; }
    }
}