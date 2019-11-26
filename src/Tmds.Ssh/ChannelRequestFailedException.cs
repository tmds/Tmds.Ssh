// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // An operation performed against a channel failed.
    public class ChannelRequestFailed : SshException
    {
        public ChannelRequestFailed(string message) : base(message) { }
        public ChannelRequestFailed(string message, Exception inner) : base(message, inner) { }
    }
}