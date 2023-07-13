// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Flags]
    public enum OpenFlags : uint
    {
        Read = 1,
        Write = 2,
        Append = 4,
        Open = 0,
        OpenOrCreate = 8,
        TruncateOrCreate = 16 | 32,
        CreateNew = 8 | 32,
    }
}