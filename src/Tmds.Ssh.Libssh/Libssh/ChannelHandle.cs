// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Runtime.InteropServices;

namespace Tmds.Ssh.Libssh;

class ChannelHandle : SafeHandle
{
    private ChannelHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    internal SessionHandle? SessionHandle { get; set; }

    protected override bool ReleaseHandle()
    {
        Interop.ssh_channel_free(handle);
        SessionHandle?.DangerousRelease();
        return true;
    }
}
