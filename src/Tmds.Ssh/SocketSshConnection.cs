// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    sealed class SocketSshConnection : SshConnection
    {
        private readonly ILogger _logger;
        private readonly SequencePool _sequencePool;
        private readonly Socket _socket;
        private Sequence _receiveBuffer;
        private static ReadOnlySpan<byte> NewLine => new byte[] { (byte)'\r', (byte)'\n' };

        public SocketSshConnection(ILogger logger, SequencePool sequencePool, Socket socket)
        {
            _logger = logger;
            _sequencePool = sequencePool;
            _socket = socket;
            _receiveBuffer = sequencePool.RentSequence();
        }

        public override async ValueTask<string> ReceiveLineAsync(int maxLength, CancellationToken ct)
        {
            while (true)
            {
                if (TryParseLine(maxLength, out string? line))
                {
                    return line!;
                }

                int received = await ReceiveAsync(ct);
                if (received == 0)
                {
                    throw new ProtocolException("Client closed connection while receiving line.");
                }
            }
        }

        private async ValueTask<int> ReceiveAsync(CancellationToken ct)
        {
            int received = await _socket.ReceiveAsync(_receiveBuffer.AllocGetMemory(), SocketFlags.None, ct);
            _receiveBuffer.AppendAlloced(received);
            return received;
        }

        private bool TryParseLine(int maxLength, out string? line)
        {
            maxLength += NewLine.Length;

            var data = _receiveBuffer.AsReadOnlySequence();
            bool lineExpected = data.Length >= maxLength;
            if (lineExpected)
            {
                // Don't look at more than maxLength data.
                data = data.Slice(maxLength);
            }

            var reader = new SequenceReader<byte>(data);
            if (reader.TryReadTo(out ReadOnlySequence<byte> lineSequence, NewLine))
            {
                // TODO convert UTF8 Exception into ProtocolException.
                line = Encoding.UTF8.GetString(lineSequence.ToArray());
                _receiveBuffer.Remove(reader.Consumed);
                return true;
            }

            if (lineExpected)
            {
                throw new ProtocolException($"Line delimited by '\\r\\n' exceeds {maxLength}");
            }

            line = null;
            return false;
        }

        public async override ValueTask<Sequence?> ReceivePacketAsync(CancellationToken ct, int maxLength)
        {
            if (maxLength == 0)
            {
                // https://tools.ietf.org/html/rfc4253#section-6.1
                // Default to the expected supported max length.
                maxLength = 35000;
            }

            while (true)
            {
                if (TryParsePacket(maxLength, out Sequence? packet))
                {
                    return packet!;
                }

                int received = await ReceiveAsync(ct);
                if (received == 0)
                {
                    if (_receiveBuffer.AsReadOnlySequence().IsEmpty)
                    {
                        return null;
                    }
                    else
                    {
                        throw new ProtocolException("Client closed connection while receiving packet.");
                    }
                }
            }
        }

        private bool TryParsePacket(int maxLength, out Sequence? packet)
        {
            // TODO: implement binary packet parsing.

            // For now: just return the whole _receiveBuffer.
            if (!_receiveBuffer.AsReadOnlySequence().IsEmpty)
            {
                packet = _receiveBuffer;
                _receiveBuffer = _sequencePool.RentSequence();
                return true;
            }

            packet = null;
            return false;
        }

        public override async ValueTask SendPacketAsync(ReadOnlySequence<byte> data, CancellationToken ct)
        {
            foreach (var memory in data)
            {
                await _socket.SendAsync(memory, SocketFlags.None, ct);
            }
        }

        public override async ValueTask WriteLineAsync(string line, CancellationToken ct)
        {
            line += "\r\n";
            await _socket.SendAsync(Encoding.UTF8.GetBytes(line), SocketFlags.None, ct);
        }

        public override void Dispose()
        {
            _receiveBuffer.Dispose();
            _socket.Dispose();
        }
    }
}
