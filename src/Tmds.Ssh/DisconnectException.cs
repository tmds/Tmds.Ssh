// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // Used as inner exception of ConnectionClosedException when peer sends disconnect message.
    [Serializable]
    public class DisconnectException : ConnectionException
    {
        public DisconnectException(string message) : base(message) { }
        public DisconnectException(string message, Exception inner) : base(message, inner) { }
    }
}