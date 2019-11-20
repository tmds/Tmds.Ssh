// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public class RemoteProcess : IDisposable
    {
        private readonly ChannelContext _context;
        private Sequence? _stdoutData;
        private Sequence? _stderrData;
        private bool _exited;

        internal RemoteProcess(ChannelContext context)
        {
            _context = context;
        }

        public int? ExitCode { get; private set; }
        public string? ExitSignal { get; private set; }

        public void Abort(Exception reason)
            => _context.Abort(reason);

        public ValueTask WriteInputAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
            => _context.SendChannelDataAsync(buffer, ct);

        public async ValueTask<(ProcessReadType readType, int bytesRead)> ReadOutputAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (buffer.Length == 0)
            {
                ThrowHelper.ThrowArgumentOutOfRange(nameof(buffer));
            }

            do
            {
                if (_stdoutData != null)
                {
                    int length = MoveDataFromSequenceToMemory(ref _stdoutData, buffer);
                    if (length != 0)
                    {
                        _context.AdjustChannelWindow(length);
                        return (ProcessReadType.StandardOutput, length);
                    }
                }

                if (_stderrData != null)
                {
                    int length = MoveDataFromSequenceToMemory(ref _stderrData, buffer);
                    if (length != 0)
                    {
                        _context.AdjustChannelWindow(length);
                        return (ProcessReadType.StandardError, length);
                    }
                }

                ProcessReadType readResult = await ReceiveUntilProcessReadResultAsync(ct);

                if (_stdoutData == null &&
                    _stderrData == null)
                {
                    return (readResult, 0);   
                }

            } while (true);

            static int MoveDataFromSequenceToMemory(ref Sequence? sequence, Memory<byte> buffer)
            {
                int length = length = (int)Math.Min(buffer.Length, sequence!.Length);
                sequence.AsReadOnlySequence().Slice(0, length).CopyTo(buffer.Span);
                sequence.Remove(length);
                if (sequence.IsEmpty)
                {
                    sequence.Dispose();
                    sequence = null;
                }
                return length;
            }
        }

        private async ValueTask<ProcessReadType> ReceiveUntilProcessReadResultAsync(CancellationToken ct)
        {
            if (_exited)
            {
                return ProcessReadType.ProcessExit;
            }

            do
            {
                using var packet = await _context.ReceivePacketAsync(ct);
                switch (packet.MessageId)
                {
                    case MessageId.SSH_MSG_CHANNEL_DATA:
                        _stdoutData = packet.MovePayload();
                        // remove SSH_MSG_CHANNEL_DATA (1), recipient channel (4), and data length (4).
                        _stdoutData.Remove(9);
                        return ProcessReadType.StandardOutput;
                    case MessageId.SSH_MSG_CHANNEL_EXTENDED_DATA:
                        // TODO
                        break;
                    case MessageId.SSH_MSG_CHANNEL_EOF:
                        return ProcessReadType.StandardOutputEof;
                    case MessageId.SSH_MSG_CHANNEL_CLOSE:
                        _exited = true;
                        return ProcessReadType.ProcessExit;
                    case MessageId.SSH_MSG_CHANNEL_REQUEST:
                        await HandleMsgChannelRequestAsync(packet, ct);
                        break;
                    default:
                        ThrowHelper.ThrowProtocolUnexpectedMessageId(packet.MessageId!.Value);
                        break;
                }
            } while (true);
        }

        private async ValueTask HandleMsgChannelRequestAsync(ReadOnlyPacket packet, CancellationToken ct)
        {
            bool want_reply = ParseAndHandleChannelRequest(packet);
            if (want_reply)
            {
                // If the request is not recognized or is not
                // supported for the channel, SSH_MSG_CHANNEL_FAILURE is returned.
                await _context.SendChannelFailureMessageAsync(ct);
            }
        }

        private bool ParseAndHandleChannelRequest(ReadOnlyPacket packet)
        {
            /*
                byte      SSH_MSG_CHANNEL_REQUEST
                uint32    recipient channel
                string    request type in US-ASCII characters only
                boolean   want reply
                ....      type-specific data follows
            */
            var reader = packet.GetReader();
            reader.ReadMessageId(MessageId.SSH_MSG_CHANNEL_REQUEST);
            reader.SkipUInt32();
            string request_type = reader.ReadUtf8String();
            bool want_reply = reader.ReadBoolean();

            switch (request_type)
            {
                case "exit-status":
                /*
                    uint32    exit_status
                */
                    ExitCode = unchecked((int)reader.ReadUInt32());
                    reader.ReadEnd();
                    break;
                case "exit-signal":
                /*
                    string    signal name (without the "SIG" prefix)
                    boolean   core dumped
                    string    error message in ISO-10646 UTF-8 encoding
                    string    language tag [RFC3066]
                */
                    ExitSignal = reader.ReadUtf8String();
                    reader.SkipBoolean();
                    reader.SkipString();
                    reader.SkipString();
                    reader.ReadEnd();
                    break;
            }

            return want_reply;
        }

        // TODO: string based methods
        // ValueTask<ProcessReadType> ReadAsync(StringBuilder standardOut, StringBuilder standardError, CancellationToken cancellationToken = default(CancellationToken));
        // ValueTask<ProcessReadType> ReadLineAsync(StringBuilder standardOut, StringBuilder standardError, CancellationToken cancellationToken = default(CancellationToken));

        public void Dispose()
        {
            _stdoutData?.Dispose();
            _stdoutData = null;

            _stderrData?.Dispose();
            _stderrData = null;

            _context.Dispose();
        }
    }
}
