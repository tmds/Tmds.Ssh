// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Flags]
    enum UnixFileTypeFilter : byte
    {
        RegularFile = 1,
        Directory = 2,
        SymbolicLink = 4,
        CharacterDevice = 8,
        BlockDevice = 16,
        Socket = 32,
        Fifo = 64,
    }

    static class UnixFileTypeFilterExtensions
    {
        internal const int TypeShift = 8;

        public static bool Matches(this UnixFileTypeFilter filter, UnixFileType type)
            => (((int)type >> TypeShift) & (int)filter) != 0;
    }
}