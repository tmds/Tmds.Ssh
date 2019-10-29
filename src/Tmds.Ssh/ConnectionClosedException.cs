// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Serializable]
    public class ConnectionClosedException : Exception
    {
        public ConnectionClosedException() { }
        public ConnectionClosedException(string message) : base(message) { }
        public ConnectionClosedException(string message, Exception inner) : base(message, inner) { }
        protected ConnectionClosedException(
            System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}