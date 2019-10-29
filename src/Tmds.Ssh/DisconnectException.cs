// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Serializable]
    public class DisconnectException : Exception
    {
        public DisconnectException() { }
        public DisconnectException(string message) : base(message) { }
        public DisconnectException(string message, Exception inner) : base(message, inner) { }
        protected DisconnectException(
            System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}