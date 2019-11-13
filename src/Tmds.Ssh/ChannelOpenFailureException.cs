// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Serializable]
    public class ChannelOpenFailureException : Exception
    {
        public ChannelOpenFailureReason Reason { get; private set; }

        public ChannelOpenFailureException(ChannelOpenFailureReason reason, string description) : base(description)
        {
            Reason = reason;
        }

        protected ChannelOpenFailureException(
            System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}