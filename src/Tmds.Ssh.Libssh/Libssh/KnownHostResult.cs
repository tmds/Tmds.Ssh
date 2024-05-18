// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh.Libssh;

enum KnownHostResult : int
{
    Error = -2,
    FileNotFound = -1,
    Unknown = 0,
    Ok,
    Changed,
    OtherType,
}
