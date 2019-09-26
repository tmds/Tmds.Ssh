// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    static class Constants
    {
        public const int StackallocThreshold = 256;
        public const int GuaranteedSizeHint = 1024;
        public const int BufferSize = 4096; // Needs to be >= GuaranteedSizeHint.
    }
}