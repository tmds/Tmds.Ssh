// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

enum ChannelOpenFailureReason
{
    AdministrativelyProhibited = 1,
    ConnectFailed = 2,
    UnknownChannelType = 3,
    ResourceShortage = 4,
}
