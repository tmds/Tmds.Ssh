// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Serializable]
    public class KeyExchangeFailedException : Exception
    {
        public SshConnectionInfo ConnectionInfo { get; }

        public KeyExchangeFailedException(string message, SshConnectionInfo connectionInfo)
            : base(message)
        {
            ConnectionInfo = connectionInfo;
        }

        public KeyExchangeFailedException(string message, SshConnectionInfo connectionInfo, Exception inner)
            : base(message, inner)
        {
            ConnectionInfo = connectionInfo;
        }
    }
}