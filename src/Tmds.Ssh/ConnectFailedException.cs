// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// Thrown when the SshClient.ConnectAsync operation fails.
class ConnectFailedException : SshConnectionException
{
    public SshConnectionInfo ConnectionInfo { get; }
    public ConnectFailedReason Reason { get; }

    public ConnectFailedException(ConnectFailedReason reason, string description, SshConnectionInfo connectionInfo, Exception inner)
        : base(FormatMessage(reason, description), inner)
    {
        ConnectionInfo = connectionInfo;
        Reason = reason;
    }

    public ConnectFailedException(ConnectFailedReason reason, string description, SshConnectionInfo connectionInfo)
        : base(FormatMessage(reason, description))
    {
        ConnectionInfo = connectionInfo;
        Reason = reason;
    }

    private static string FormatMessage(ConnectFailedReason reason, string description)
        => $"The connection could not be established - {reason} - {description}";
}
