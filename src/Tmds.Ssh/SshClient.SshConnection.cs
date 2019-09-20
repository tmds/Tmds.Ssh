// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public sealed partial class SshClient
    {
        sealed class SocketSshConnection : SshConnection
        {
            private readonly SshClient _client;
            private readonly Socket _socket;

            public SocketSshConnection(SshClient client, Socket socket)
            {
                _client = client;
                _socket = socket;
            }

            public override ValueTask ReceiveLineAsync(StringBuilder sb, int maxLength, CancellationToken ct)
                => throw new NotImplementedException();
            public override ValueTask<Sequence> ReceivePacketAsync(CancellationToken ct)
                => throw new NotImplementedException();
            public override ValueTask SendPacketAsync(ReadOnlySequence<byte> data, CancellationToken ct)
                => throw new NotImplementedException();
            public override ValueTask WriteLineAsync(string line, CancellationToken ct)
                => throw new NotImplementedException();

            public override void Dispose()
            {
                _socket.Dispose();
            }
        }
    }
}
