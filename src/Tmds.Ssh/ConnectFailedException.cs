// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    // Thrown when the SshClient.ConnectAsync operation fails.
    [Serializable]
    public class ConnectFailedException : ConnectionException
    {
        public SshConnectionInfo ConnectionInfo { get; }
        public ConnectFailedReason FailedReason { get; }

        public ConnectFailedException(ConnectFailedReason reason, string message, SshConnectionInfo connectionInfo, Exception inner)
            : base(message, inner)
        {
            ConnectionInfo = connectionInfo;
            FailedReason = reason;
        }

        public ConnectFailedException(ConnectFailedReason reason, string message, SshConnectionInfo connectionInfo)
            : base(message)
        {
            ConnectionInfo = connectionInfo;
            FailedReason = reason;
        }
    }
}