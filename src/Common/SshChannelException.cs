// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    public class SshChannelException : SshException
    {
        internal SshChannelException(string message) : base(message) { }
        internal SshChannelException(string message, System.Exception? inner) : base(message, inner) { }
    }
}