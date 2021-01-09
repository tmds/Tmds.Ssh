// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Flags]
    enum PollFlags
    {
        None = 0,
        ReadPending = 0x2,
        WritePending = 0x8,
    }
}