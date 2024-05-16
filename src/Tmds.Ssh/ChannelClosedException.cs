// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // Channel was closed by the peer. Data may still be pending for receive.
    // No more data can be sent.
    [Serializable]
    public class ChannelClosedException : SshException
    {
        public ChannelClosedException() : base("Channel closed by peer.") { }
        public ChannelClosedException(string message) : base(message) { }
        public ChannelClosedException(string message, Exception inner) : base(message, inner) { }
    }
}