// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh;

[Flags]
public enum OpenMode
{
    Default = 0,
    Append = 1,
    Truncate = 2
}
