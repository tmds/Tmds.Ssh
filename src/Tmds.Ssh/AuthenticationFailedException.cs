// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Serializable]
    public class AuthenticationFailedException : Exception
    {
        public AuthenticationFailedException() { }
        public AuthenticationFailedException(string message) : base(message) { }
        public AuthenticationFailedException(string message, Exception inner) : base(message, inner) { }
        protected AuthenticationFailedException(
            System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}