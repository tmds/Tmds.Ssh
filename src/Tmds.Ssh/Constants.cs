// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    static class Constants
    {
        public const int StackallocThreshold = 256;
        public const int GuaranteedSizeHint = 1024;
        public const int PreAuthMaxPacketLength = 35000; // https://tools.ietf.org/html/rfc4253#section-6.1
        public const int MaxPacketLength = PreAuthMaxPacketLength;
        public const int MaxDataPacketSize = 32 * 1024;
        public const int BufferSize = 4096;          // Needs to be >= GuaranteedSizeHint.
        public const int MaxNameLength = 128;        // Arbitrary limit, may be increased.
        public const int MaxECPointLength = 128 + 1; // Arbitrary limit, may be increased.
        public const int MaxKeyLength = 1024;        // Arbitrary limit, may be increased.
    }
}