// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

static class SentinelExceptions
{
    // Sentinel exceptions used as _abortReason by SshSession. Note: these get logged!
    public static readonly Exception ClosedByPeer = new SshConnectionClosedException(SshConnectionClosedException.ConnectionClosedByPeer);
    public static readonly Exception ClosedByKeepAliveTimeout = new SshConnectionClosedException(SshConnectionClosedException.ConnectionClosedByKeepAliveTimeout);
    public static readonly ObjectDisposedException ClientDisposedException = SshClient.NewObjectDisposedException();

    // Sentinel stop reasons for RemoteListener. Values don't matter, use exceptions instances from above.
    public static Exception ConnectionClosed => ClosedByKeepAliveTimeout;
    public static Exception Disposed => ClientDisposedException;
    public static Exception Stopped => ClosedByPeer;
}
