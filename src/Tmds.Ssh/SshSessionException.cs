// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    public class SshSessionException : SshException
    {
        internal SshSessionException(string message) : base(message) { }
        internal SshSessionException(string message, System.Exception inner) : base(message, inner) { }
    }
}