using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Buffers;
using System.Buffers.Binary;

namespace Tmds.Ssh
{
    abstract class SftpOperation
    {
        public abstract ValueTask HandleResponse(SftpPacketType type, ReadOnlySequence<byte> fields);

        protected static Exception CreateExceptionForStatus(ReadOnlySequence<byte> fields)
        {
            return new SshException("TODO"); // TODO: use fields
        }

        protected static Exception CreateExceptionForUnexpectedType(SftpPacketType type)
        {
            return new ProtocolException($"Unexpected response type: {type}");
        }
    }

    public partial class SftpClient : IDisposable
    {
        // SSH_MSG_CHANNEL_DATA          (1)
        // RemoteChannel                 (4)
        // SSH_MSG_CHANNEL_DATA length   (4)
        // SFTP length                   (4)
        const int DataHeaderLength = 13;
        const int SftpVersion = 3;
        private readonly ChannelContext _context;
        private readonly Task _receiveLoopTask;
        private int _requestId;
        private ConcurrentDictionary<uint, SftpOperation> _operations;

        private ValueTask SendRequestAsync(Packet packet, SftpOperation operation)
        {
            /*
                0: SSH_MSG_CHANNEL_DATA  (1)
                1: RemoteChannel         (4)
                5: DATA length           (4)
                9: SFTP length           (4)
                13: SFTP packet type     (1) ] // Already filled in.
                14: SFTP request id      (4)
            */
            uint requestId = unchecked((uint)Interlocked.Increment(ref _requestId));
            Span<byte> header = packet.PayloadHeader;
            header[0] = (byte)MessageId.SSH_MSG_CHANNEL_DATA;
            BinaryPrimitives.WriteUInt32BigEndian(header.Slice(1), _context.RemoteChannel);
            int dataLength = (int)packet.PayloadLength - 9;
            BinaryPrimitives.WriteUInt32BigEndian(header.Slice(5), (uint)dataLength);
            BinaryPrimitives.WriteUInt32BigEndian(header.Slice(9), (uint)(dataLength - 4));
            BinaryPrimitives.WriteUInt32BigEndian(header.Slice(14), requestId);

            _operations.TryAdd(requestId, operation);

            return _context.SendChannelDataAsync(packet, default(CancellationToken)); // TODO: cancellation
        }

        internal SftpClient(ChannelContext context)
        {
            _context = context;
            _receiveLoopTask = ReceiveLoopAsync();
            _operations = new ConcurrentDictionary<uint, SftpOperation>();
        }

        // public async Task InitAsync(CancellationToken ct)
        // {
        //     await _context.SftpInitMessageAsync(3, ct).ConfigureAwait(false);
        //     // TODO add server negotiation in case server would have min. version < 3, but was able to do a version 3 aswell
        //     int serverVersion = await _context.ReceiveServerVersionAsync("Failed to negotiate SFTP", ct).ConfigureAwait(false);

        //     if (serverVersion != SftpVersion)
        //         ThrowHelper.ThrowNotSupportedException("Server SFTP version is not supported");
        // }

        public void Dispose()
        {
            _context?.Dispose();
        }

        private async Task ReceiveLoopAsync()
        {
            try
            {
                MessageId messageId;
                do
                {
                    using var packet = await _context.ReceivePacketAsync(ct: default).ConfigureAwait(false);
                    messageId = packet.MessageId!.Value;

                    if (messageId == MessageId.SSH_MSG_CHANNEL_DATA)
                    {
                        await HandleChannelData(packet.Move()).ConfigureAwait(false);
                    }
                    else
                    {
                        // Nothing yet
                    }

                } while (messageId != MessageId.SSH_MSG_CHANNEL_CLOSE);

            }
            catch (Exception e)
            {
                throw e;
            }
        }

        private async ValueTask HandleChannelData(Packet packet)
        {
            /*
                byte      SSH_MSG_CHANNEL_DATA
                uint32    recipient channel
                string    data
            */
            using Sequence payload = packet.MovePayload();
            payload.Remove(9);
            while (ReadSftpPacket(payload, out SftpPacketType type, out uint requestId, out ReadOnlySequence<byte> fields, out uint consumed))
            {
                if (_operations.TryGetValue(requestId, out SftpOperation operation))
                {
                    await operation.HandleResponse(type, fields);
                }
                payload.Remove(consumed);
            }
        }

        private bool ReadSftpPacket(Sequence payload, out SftpPacketType type, out uint requestId, out ReadOnlySequence<byte> fields, out uint consumed)
        {
            if (payload.IsEmpty)
            {
                type = default;
                requestId = 0;
                fields = default;
                consumed = 0;
                return false;
            }
            /*
                uint32           length        // The length of the entire packet, excluding the length field
                byte             type
                uint32           request-id
                    ... type specific fields ...
            */
            var reader = new SequenceReader(payload);
            uint length = reader.ReadUInt32();
            type = (SftpPacketType)reader.ReadByte();
            requestId = reader.ReadUInt32();
            fields = payload.AsReadOnlySequence().Slice(9, length - 5);
            consumed = 4 + length;
            return true;
        }
    }
}