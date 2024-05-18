// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh.Libssh;

enum AuthResult : int
{
    Success,
    Denied,
    Partial,
    Info,
    Again,
    Error = -1,
}
