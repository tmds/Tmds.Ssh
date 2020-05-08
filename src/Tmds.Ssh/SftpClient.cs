// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

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
        public abstract ValueTask HandleResponse(SftpPacketType type, ReadOnlySequence<byte> fields, SftpClient client);

        protected static Exception CreateExceptionForStatus(SftpErrorCode errorCode, string? errorMessage)
        {
            return new SftpException(errorCode, errorMessage);
        }

        protected static Exception CreateExceptionForStatus(ReadOnlySequence<byte> fields)
        {
            (SftpErrorCode errorCode, string? errorMessage) status = ParseStatusFields(fields);
            return new SftpException(status.errorCode, status.errorMessage);
        }

        protected static Exception CreateExceptionForUnexpectedType(SftpPacketType type)
        {
            return new ProtocolException($"Unexpected response type: {type}");
        }

        protected static (SftpErrorCode errorCode, string? errorMessage) ParseStatusFields(ReadOnlySequence<byte> fields)
        {
            /*
                uint32 error/status code
                string error message
                string language tag (ignored)
            */
            var reader = new SequenceReader(fields);
            var errorCode = (SftpErrorCode)reader.ReadUInt32();
            string? errorMessage = reader.ReadUtf8String();
            if (errorMessage == string.Empty)
                errorMessage = null;
            return (errorCode, errorMessage);
        }
    }

    public sealed partial class SftpClient : IDisposable
    {
        // SSH_MSG_CHANNEL_DATA          (1)
        // RemoteChannel                 (4)
        // SSH_MSG_CHANNEL_DATA length   (4)
        // SFTP length                   (4)
        const int DataHeaderLength = 13;
        const uint SftpVersion = 3;
        private readonly ChannelContext _context;
        private Task? _receiveLoopTask;
        private int _requestId;
        private readonly ConcurrentDictionary<uint, SftpOperation> _operations;

        private ValueTask SendRequestAsync(Packet packet, SftpOperation operation)
        {
            /*
                0: SSH_MSG_CHANNEL_DATA  (1)
                1: RemoteChannel         (4)
                5: DATA length           (4)
                9: SFTP length           (4)
                13: SFTP packet type     (1) // Already filled in.
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
            _operations = new ConcurrentDictionary<uint, SftpOperation>();
        }

        internal async Task InitAsync(CancellationToken ct)
        {
            await SftpInitMessageAsync(SftpVersion, ct).ConfigureAwait(false);
            uint serverVersion = await ReceiveServerVersionAsync("Failed to negotiate SFTP", ct);

            if (serverVersion != SftpVersion)
                ThrowHelper.ThrowNotSupportedException("Server SFTP version is not supported");

            _receiveLoopTask = ReceiveLoopAsync();
        }

        public void Dispose()
        {
            // TODO? Deal with stopping ReceiveLoopAsync()
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

                } while (messageId != MessageId.SSH_MSG_CHANNEL_CLOSE);

            }
            catch (Exception e)
            {
                // TODO Handling
                // The handling should avoid new operations being started, 
                // and an exception to be thrown for all on-going requests.
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
                    await operation.HandleResponse(type, fields, this);
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
            type = reader.ReadSftpPacketType();
            requestId = reader.ReadUInt32();
            fields = payload.AsReadOnlySequence().Slice(9, length - 5);
            consumed = 4 + length;
            return true;
        }

        private async ValueTask<uint> ReceiveServerVersionAsync(string failureMessage, CancellationToken ct)
        {
            using var packet = await _context.ReceivePacketAsync(ct).ConfigureAwait(false);

            return ParseSftpVersion(packet, failureMessage);

            static uint ParseSftpVersion(ReadOnlyPacket packet, string failureMessage)
            {
                /*
                            byte            SSH_MSG_CHANNEL_DATA
                            uint32          recipient channel
                            string          data

                            uint32          SftpLength
                            byte            SftpType
                            uint32          SftpVersion
                            string          extension-name
                            string          extension-data
                */
                var reader = packet.GetReader();
                reader.ReadMessageId(MessageId.SSH_MSG_CHANNEL_DATA);
                reader.Skip(12);
                reader.ReadSftpPacketType(SftpPacketType.SSH_FXP_VERSION);
                var version = reader.ReadUInt32();
                return version;
            }
        }

        private ValueTask SftpInitMessageAsync(uint version, CancellationToken ct)
        {
            return _context.SendChannelDataAsync(CreatePacket(_context, version), ct);

            static Packet CreatePacket(ChannelContext context, uint version)
            {
                /*
                    byte        SSH_MSG_CHANNEL_DATA
                    uint32      recipient channel
                    uint32      length
                    byte        SSH_FXP_INIT
                    uint32      version
                */
                using var packet = context.RentPacket();
                var writer = packet.GetWriter();
                writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_DATA);
                writer.WriteUInt32(context.RemoteChannel);
                writer.WriteUInt32(9); // length
                writer.WriteUInt32(5); // length
                writer.WriteSftpPacketType(SftpPacketType.SSH_FXP_INIT);
                writer.WriteUInt32(version); // version
                return packet.Move();
            }
        }

    }
}