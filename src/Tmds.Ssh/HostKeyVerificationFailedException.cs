// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Text;

namespace Tmds.Ssh
{
    [Serializable]
    public class HostKeyVerificationFailedException : KeyExchangeFailedException
    {
        public HostKeyVerificationFailedException(SshConnectionInfo connectionInfo)
            : base(CreateMessage(connectionInfo), connectionInfo)
        { }

        public HostKeyVerificationFailedException(SshConnectionInfo connectionInfo, Exception inner)
            : base(CreateMessage(connectionInfo), connectionInfo, inner)
        { }

        private static string CreateMessage(SshConnectionInfo connectionInfo)
        {
            StringBuilder message = new StringBuilder();
            message.Append("The host '");
            message.Append(connectionInfo.Host);
            if (connectionInfo.Port != 22)
            {
                message.Append(':');
                message.Append(connectionInfo.Port);
            }
            message.Append(' ');
            message.Append(connectionInfo.SshKey!.Type);
            message.Append(' ');
            message.Append(Convert.ToBase64String(connectionInfo.SshKey.Key));
            message.Append("\' is ");
            message.Append(connectionInfo.KeyVerificationResult);
            message.Append(".");
            return message.ToString();
        }
    }
}