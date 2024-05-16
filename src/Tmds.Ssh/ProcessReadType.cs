// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    public enum ProcessReadType
    {
        // StandardOutputEof = -2
        ProcessExit = -1,

        StandardOutput = 1,
        StandardError = 2
    }
}