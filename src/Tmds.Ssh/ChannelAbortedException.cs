// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Serializable]
    public class ChannelAbortedException : Exception
    {
        public ChannelAbortedException() { }
        public ChannelAbortedException(string message) : base(message) { }
        public ChannelAbortedException(string message, Exception inner) : base(message, inner) { }
        protected ChannelAbortedException(
            System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}