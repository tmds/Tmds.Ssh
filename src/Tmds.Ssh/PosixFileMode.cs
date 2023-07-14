// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Flags]
    public enum PosixFileMode
    {
        None = 0,
        OtherExecute = 1,
        OtherWrite = 2,
        OtherRead = 4,
        GroupExecute = 8,
        GroupWrite = 16,
        GroupRead = 32,
        UserExecute = 64,
        UserWrite = 128,
        UserRead = 256,
        StickyBit = 512,
        SetGroup = 1024,
        SetUser = 2048,

        RegularFile = 0x8000,
        Directory = 0x4000,
        SymbolicLink = 0xa000,
        CharacterDevice = 0x2000,
        BlockDevice = 0x6000,
        Socket = 0xc000,
        Fifo = 0x1000,
    }
}