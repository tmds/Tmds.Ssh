// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh.Libssh;

[Flags]
enum StatusFlags
{
    Closed = 1,
    ReadPending = 2,
    ClosedError = 4,
    WritePending = 8
}
