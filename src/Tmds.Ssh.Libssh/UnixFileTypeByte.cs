// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    enum UnixFileTypeByte : byte
    {
        RegularFile = 0x8,
        Directory = 0x4,
        SymbolicLink = 0xa,
        CharacterDevice = 0x2,
        BlockDevice = 0x6,
        Socket = 0xc,
        Fifo = 0x1,
    }
}