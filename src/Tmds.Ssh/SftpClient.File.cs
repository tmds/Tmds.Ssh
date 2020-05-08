// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;
using System.Buffers.Binary;

namespace Tmds.Ssh
{
    public sealed class SftpFile
    {
        private readonly byte[] _handle;
        private readonly SftpClient _client;

        internal SftpFile(byte[] handle, SftpClient client)
        {
            _handle = handle;
            _client = client;
        }

        public ValueTask<bool> CloseAsync() => _client.SendCloseHandleAsync(_handle);
    }

    public enum SftpOpenFlags
    {
        Read = 0x00000001,
        Write = 0x00000002,
        Append = 0x00000004,
        CreateNewOrOpen = 0x00000008,
        Truncate = 0x00000010,
        CreateNew = 0x00000020 | CreateNewOrOpen,
    }

    public partial class SftpClient
    {
        // TODO add CancellationToken
        public async ValueTask<SftpFile> OpenFileAsync(string path, SftpOpenFlags openFlags)
        {
            using var packet = CreateOpenMessage(path, openFlags);
            var operation = new OpenFileOperation();

            await SendRequestAsync(packet.Move(), operation);

            return await operation.Task;

            Packet CreateOpenMessage(string filename, SftpOpenFlags flags)
            {
                using var packet = _context.RentPacket();
                var writer = packet.GetWriter();
                writer.Reserve(DataHeaderLength);

                /*
                    SSH_FXP_OPEN
                    uint32        id
                    string        filename
                    uint32        pflags
                    ATTRS         attrs
                */

                writer.WriteSftpPacketType(SftpPacketType.SSH_FXP_OPEN);
                writer.WriteUInt32(0);
                writer.WriteString(filename);
                writer.WriteUInt32((int)flags);
                writer.WriteUInt32(0);
                return packet.Move();
            }
        }

        // TODO add CancellationToken
        // This can be used for any handle, so also for directories
        internal async ValueTask<bool> SendCloseHandleAsync(byte[] handle)
        {
            using var packet = CreateCloseMessage(handle);
            var operation = new CloseHandleOperation();

            await SendRequestAsync(packet.Move(), operation);

            return await operation.Task;

            Packet CreateCloseMessage(byte[] handle)
            {
                using var packet = _context.RentPacket();
                var writer = packet.GetWriter();
                writer.Reserve(DataHeaderLength);

                /*
                    SSH_FXP_CLOSE
                    uint32        id
                    string        handle
                */

                writer.WriteSftpPacketType(SftpPacketType.SSH_FXP_CLOSE);
                writer.WriteUInt32(0);
                writer.WriteString(handle);
                return packet.Move();
            }
        }
    }

    sealed class OpenFileOperation : SftpOperation
    {
        private TaskCompletionSource<SftpFile> _tcs = new TaskCompletionSource<SftpFile>();

        public override ValueTask HandleResponse(SftpPacketType type, ReadOnlySequence<byte> fields, SftpClient client)
        {
            if (type == SftpPacketType.SSH_FXP_STATUS)
            {
                _tcs.SetException(CreateExceptionForStatus(fields));
            }
            else if (type == SftpPacketType.SSH_FXP_HANDLE)
            {
                var handle = ParseHandleFields(fields);
                _tcs.SetResult(new SftpFile(handle, client));
            }
            else
            {
                _tcs.SetException(CreateExceptionForUnexpectedType(type));
            }

            return default;
        }

        public Task<SftpFile> Task => _tcs.Task;

        static byte[] ParseHandleFields(ReadOnlySequence<byte> fields)
        {
            /*
                byte   SSH_FXP_HANDLE
                uint32 request-id

                string handle
            */
            var reader = new SequenceReader(fields);
            byte[] handle = reader.ReadStringAsBytes().ToArray();
            return handle;
        }
    }

    // This can be used for any handle, so also for directories
    sealed class CloseHandleOperation : SftpOperation
    {
        private TaskCompletionSource<bool> _tcs = new TaskCompletionSource<bool>();

        public override ValueTask HandleResponse(SftpPacketType type, ReadOnlySequence<byte> fields, SftpClient client)
        {
            if (type == SftpPacketType.SSH_FXP_STATUS)
            {
                (SftpErrorCode errorCode, string? errorMessage) status = ParseStatusFields(fields);

                if (status.errorCode == SftpErrorCode.SSH_FX_OK)
                {
                    _tcs.SetResult(true);
                }
                else
                {
                    CreateExceptionForStatus(status.errorCode, status.errorMessage);
                }
            }
            else
            {
                _tcs.SetException(CreateExceptionForUnexpectedType(type));
            }
            return default;
        }

        public Task<bool> Task => _tcs.Task;

    }
}