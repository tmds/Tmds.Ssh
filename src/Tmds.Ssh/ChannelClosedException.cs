// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Serializable]
    public class ChannelClosedException : Exception
    {
        public ChannelClosedException() : base("Channel closed by peer.") { }
        public ChannelClosedException(string message) : base(message) { }
        public ChannelClosedException(string message, Exception inner) : base(message, inner) { }
        protected ChannelClosedException(
            System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}