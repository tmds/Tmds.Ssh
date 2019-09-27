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

        private static ReadOnlySpan<byte> NewLine => new byte[] { (byte)'\r', (byte)'\n' };
        private static readonly UTF8Encoding s_utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        private readonly ILogger _logger;
        private readonly SequencePool _sequencePool;
        private readonly Socket _socket;
        private readonly Sequence _receiveBuffer;
        private readonly Sequence _sendBuffer;
        private PacketDecoder _decoder;
        private PacketEncoder _encoder;

        public SocketSshConnection(ILogger logger, SequencePool sequencePool, Socket socket)
        {
            _logger = logger;
            _sequencePool = sequencePool;
            _socket = socket;
            _receiveBuffer = sequencePool.RentSequence();
            _sendBuffer = sequencePool.RentSequence();
            _decoder = new PacketDecoder();
            _encoder = new PacketEncoder();
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
            var memory = _receiveBuffer.AllocGetMemory();
            int received = await _socket.ReceiveAsync(memory, SocketFlags.None, ct);
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
                data = data.Slice(0, maxLength);
            }

            var reader = new SequenceReader<byte>(data);
            if (reader.TryReadTo(out ReadOnlySequence<byte> lineSequence, NewLine))
            {
                try
                {
                    line = s_utf8Encoding.GetString(lineSequence.ToArray());
                }
                catch (DecoderFallbackException)
                {
                    ThrowHelper.ThrowProtocolInvalidUtf8();
                    throw;
                }
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
                if (_decoder.TryDecodePacket(_receiveBuffer, _sequencePool, maxLength, out Sequence? packet))
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

        public override async ValueTask SendPacketAsync(ReadOnlySequence<byte> data, CancellationToken ct)
        {
            _encoder.Encode(data, _sendBuffer);
            var encodedData = _sendBuffer.AsReadOnlySequence();

            if (encodedData.IsSingleSegment)
            {
                await _socket.SendAsync(encodedData.First, SocketFlags.None, ct);
            }
            else
            {
                foreach (var memory in encodedData)
                {
                    await _socket.SendAsync(memory, SocketFlags.None, ct);
                }
            }

            _sendBuffer.Clear();
        }

        public override async ValueTask WriteLineAsync(string line, CancellationToken ct)
        {
            line += "\r\n";
            await _socket.SendAsync(Encoding.UTF8.GetBytes(line), SocketFlags.None, ct);
        }

        public override void Dispose()
        {
            _receiveBuffer.Dispose();
            _sendBuffer.Dispose();
            _encoder.Dispose();
            _decoder.Dispose();
            _socket.Dispose();
        }
    }
}
