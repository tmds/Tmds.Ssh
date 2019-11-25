// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // Base class for exceptions that indicate the channel no longer works.
    [Serializable]
    public class ChannelException : SshException
    {
        internal ChannelException(string message) : base(message) { }
        internal ChannelException(string message, Exception inner) : base(message, inner) { }
    }
}