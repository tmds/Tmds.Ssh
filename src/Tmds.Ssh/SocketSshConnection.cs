// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

sealed class SocketSshConnection : StreamSshConnection
{
    private readonly Socket _socket;

    public SocketSshConnection(ILogger<SshClient> logger, SequencePool sequencePool, Socket socket) :
        base(logger, sequencePool, new NetworkStream(socket))
    {
        _socket = socket;
    }

    protected override void Dispose(bool isDisposing)
    {
        base.Dispose(isDisposing);
        if (isDisposing)
        {
            _socket.Dispose();
        }
    }
}
