// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// Thrown for SSH_MSG_DISCONNECT.
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
