// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Serializable]
    public class KeyExchangeFailedException : Exception
    {
        public KeyExchangeFailedException() { }
        public KeyExchangeFailedException(string message) : base(message) { }
        public KeyExchangeFailedException(string message, Exception inner) : base(message, inner) { }
        protected KeyExchangeFailedException(
            System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}