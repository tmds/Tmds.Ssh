// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Exception thrown when an operation failed because the SSH connection is already closed.
/// </summary>
public class SshConnectionClosedException : SshConnectionException
{
    internal const string ConnectionClosedByPeer = "Connection closed by peer.";
    internal const string ConnectionClosedByKeepAliveTimeout = "Connection closed due to keep alive timeout.";
    internal const string ConnectionClosedByAbort = "Connection closed due to an unexpected error.";
    internal const string ConnectionClosedByDispose = "Connection closed by dispose.";

    internal SshConnectionClosedException(string message, System.Exception? inner = null) : base(message, inner) { }
}
