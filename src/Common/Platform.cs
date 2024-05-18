// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Runtime.InteropServices;

namespace Tmds.Ssh;

static class Platform
{
    public static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
}
