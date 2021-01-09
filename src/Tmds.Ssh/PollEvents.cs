// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Flags]
    enum PollEvents
    {
        PollIn = 1 << 0,
        PollOut = 1 << 1,
        PollErr = 1 << 2,
    }
}