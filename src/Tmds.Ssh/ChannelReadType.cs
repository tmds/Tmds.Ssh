// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    public enum ChannelReadType // TODO: internal
    {
        StandardOutput = 1,
        StandardError = 2,
        Eof = 3,
        Closed = 4,
    }
}