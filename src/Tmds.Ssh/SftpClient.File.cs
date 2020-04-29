using System;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;
using System.Buffers.Binary;

namespace Tmds.Ssh
{
    public class SftpFile
    {
        private byte[] handle;
        internal SftpFile(byte[] handle)
        {
            this.handle = handle;
        }
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
        public async Task<SftpFile> OpenFileAsync(string path, SftpOpenFlags openFlags)
        {
            using var packet = CreateOpenMessage(path, openFlags);
            var operation = new OpenFileOperation();

            await SendRequestAsync(packet.Move(), operation);

            return await operation.Task;

            // int requestId = GetNextRequestId();

            // _operations.TryAdd(requestId, operation);

            // await _context.SftpOpenFileMessageAsync((UInt32)requestId, path, openFlags, attributes, default);
            // return await operation.Task;
        }

        private Packet CreateOpenMessage(string filename, SftpOpenFlags flags)
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

            writer.WriteByte((byte)SftpPacketType.SSH_FXP_OPEN);
            writer.WriteUInt32(0);
            writer.WriteString(filename);
            writer.WriteUInt32((int)flags);
            writer.WriteUInt32(0);
            return packet.Move();
        }
    }

    class OpenFileOperation : SftpOperation
    {
        private TaskCompletionSource<SftpFile> _tcs = new TaskCompletionSource<SftpFile>();

        public override ValueTask HandleResponse(SftpPacketType type, ReadOnlySequence<byte> fields)
        {
            if (type == SftpPacketType.SSH_FXP_STATUS)
            {
                _tcs.SetException(CreateExceptionForStatus(fields));
            }
            else if (type == SftpPacketType.SSH_FXP_HANDLE)
            {
                var handle = ParseHandleFields(fields);
                _tcs.SetResult(new SftpFile(handle));
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
}