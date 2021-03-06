// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Runtime.InteropServices;

namespace Tmds.Ssh
{
    class SessionHandle : SafeHandle
    {
        private SessionHandle() : base(IntPtr.Zero, ownsHandle: true) {}

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Interop.ssh_free(handle);
            return true;
        }
    }
}