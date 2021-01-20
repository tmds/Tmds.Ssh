// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    public class SshSessionClosedException : SshSessionException
    {
        internal SshSessionClosedException(SshSessionException? closeReason = null) : base(GetMessage(closeReason), inner: null) { }

        static string GetMessage(SshSessionException? closeReason)
            => closeReason == null ? "Session closed." : $"Session closed ({closeReason.Message}).";
     }
}