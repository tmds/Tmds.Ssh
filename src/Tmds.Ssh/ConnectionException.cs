// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // Base class for exceptions that indicate the connection no longer works.
    [Serializable]
    public class ConnectionException : SshException
    {
        internal ConnectionException(string message) : base(message) { }
        internal ConnectionException(string message, Exception inner) : base(message, inner) { }
    }
}