// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    static class MessageNumber
    {
        public const byte SSH_MSG_KEXINIT = 20;
        public const byte SSH_MSG_KEX_ECDH_INIT = 30;
        public const byte SSH_MSG_KEX_ECDH_REPLY = 31;
        public const byte SSH_MSG_NEWKEYS = 21;
    }
}