// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh.Managed
{
    // Thrown for SSH_MSG_DISCONNECT.
    [Serializable]
    class DisconnectException : SshConnectionException
    {
        public DisconnectReason Reason { get; }

        public DisconnectException(DisconnectReason reason, string description)
            : base(FormatMessage(reason, description))
        {
            Reason = reason;
        }

        private static string FormatMessage(DisconnectReason reason, string description)
            => $"The connection was closed by the peer - {reason} - {description}";
    }
}