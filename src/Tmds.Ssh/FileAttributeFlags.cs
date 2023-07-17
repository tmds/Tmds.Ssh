// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

enum FileAttributeFlags : uint
{
    SSH_FILEXFER_ATTR_SIZE = 0x00000001,
    SSH_FILEXFER_ATTR_UIDGID = 0x00000002,
    SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004,
    SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008,
    SSH_FILEXFER_ATTR_EXTENDED = 0x80000000,
}