// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh;

public class SshSessionClosedException : SshSessionException
{
    internal SshSessionClosedException(Exception? closeReason = null) : base(GetMessage(closeReason), inner: closeReason) { }

    static string GetMessage(Exception? closeReason)
        => closeReason == null ? "Session closed." : $"Session closed ({closeReason.Message}).";
}
