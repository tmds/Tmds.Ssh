// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // Channel is no longer usable.
    [Serializable]
    public class ChannelAbortedException : ChannelException
    {
        public ChannelAbortedException(string message) : base(message) { }
        public ChannelAbortedException(string message, Exception inner) : base(message, inner) { }
    }
}