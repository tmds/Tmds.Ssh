// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    public enum UnixFileType
    {
        RegularFile = 0x8000,
        Directory = 0x4000,
        SymbolicLink = 0xa000,
        CharacterDevice = 0x2000,
        BlockDevice = 0x6000,
        Socket = 0xc000,
        Fifo = 0x1000,
    }
}