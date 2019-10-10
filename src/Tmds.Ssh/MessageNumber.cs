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
        public const byte SSH_MSG_USERAUTH_REQUEST = 50;
        public const byte SSH_MSG_SERVICE_REQUEST = 5;
        public const byte SSH_MSG_SERVICE_ACCEPT = 6;
        public const byte SSH_MSG_USERAUTH_FAILURE = 51;
        public const byte SSH_MSG_USERAUTH_SUCCESS = 52;
        public const byte SSH_MSG_USERAUTH_BANNER = 53;
    }
}