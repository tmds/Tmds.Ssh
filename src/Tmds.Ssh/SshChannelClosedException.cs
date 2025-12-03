// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Exception thrown when an operation failed because the SSH channel is already closed.
/// </summary>
public class SshChannelClosedException : SshChannelException
{
    internal const string ChannelClosedByPeer = "Channel closed by peer.";
    internal const string ChannelClosedByDispose = "The channel was disposed.";
    internal const string ChannelClosedByAbort = "Channel closed due to an unexpected error.";
    internal const string ChannelClosedByCancel = "Channel closed due to a cancelled read/write operation.";

    internal SshChannelClosedException(string message) : base(message) { }
    internal SshChannelClosedException(string message, System.Exception? inner) : base(message, inner) { }
}
