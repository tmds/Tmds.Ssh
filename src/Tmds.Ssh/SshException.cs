// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // Base class for exceptions.
    [Serializable]
    public class SshException : Exception
    {
        internal SshException(string message) : base(message) { }
        internal SshException(string message, Exception inner) : base(message, inner) { }
    }
}