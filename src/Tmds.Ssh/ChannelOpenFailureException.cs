// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // The channel could not be opened.
    [Serializable]
    public class ChannelOpenFailureException : ChannelException
    {
        public ChannelOpenFailureReason Reason { get; private set; }

        public ChannelOpenFailureException(ChannelOpenFailureReason reason, string description) : base(description)
        {
            Reason = reason;
        }
    }
}