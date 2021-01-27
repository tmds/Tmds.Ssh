// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Runtime.InteropServices;

namespace Tmds.Ssh
{
    class SshKeyHandle : SafeHandle
    {
        private SshKeyHandle() : base(IntPtr.Zero, ownsHandle: true) {}

        public SshKeyHandle(IntPtr handle, bool ownsHandle) : base(handle, ownsHandle) {}

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Interop.ssh_key_free(handle);
            return true;
        }
    }
}