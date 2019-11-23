// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public class RemoteProcess : IDisposable
    {
        const int SSH_EXTENDED_DATA_STDERR = 1;

        enum ReadStatus
        {
            Initial,
            ReadRaw,
            ReadStringToEnd,
            ReadLine,
            ReadThrewException
        }

        private readonly ChannelContext _context;
        private Sequence? _stdoutData;
        private Sequence? _stderrData;
        private int _exited;
        private int _stdoutEof;
        private StreamWriter? _stdInWriter;
        private Encoding _standardInputEncoding;
        private Encoding _standardErrorEncoding;
        private Encoding _standardOutputEncoding;
        private LineDecoder _stdoutDecoder;
        private LineDecoder _stderrDecoder;
        private bool _ignoreStdout;
        private bool _ignoreStderr;
        private ReadStatus _readStatus;

        struct LineDecoder : IDisposable
        {
            private char[]? _buffer;
            private int _offset;
            private int _length;
            private bool _mayHaveNewline;
            private bool _skipNewline;
            private Decoder? _decoder;

            public bool IsInitialized => _decoder != null;

            private Span<char> CharsRead => _buffer.AsSpan(_offset, _length);

            public void Initialize(Encoding encoding)
            {
                if (_decoder == null)
                {
                    _decoder = encoding.GetDecoder();
                }
            }

            public void Dispose()
            {
                if (_buffer != null)
                {
                    ArrayPool<char>.Shared.Return(_buffer);
                    _buffer = null;
                }
            }

            public (int bytesRead, string? line) TryDecodeLine(Sequence? sequence, bool eof)
            {
                string? line;

                // _mayHaveNewline will be set if this method managed to decode a line.
                // so we inspect the remaining data on the next call.
                // If we don't find a new line, we don't need to look for one on the next call.
                if (_mayHaveNewline)
                {
                    if (TryFindNewline(inspected: 0, out line))
                    {
                        return (0, line);
                    }
                    _mayHaveNewline = false;
                }

                int bytesDecoded = 0;
                line = null;

                if (sequence != null)
                {
                    ReadOnlySequence<byte> roSequence = sequence.AsReadOnlySequence();
                    if (roSequence.IsSingleSegment)
                    {
                        if (TryDecodeAndFindNewLine(roSequence.FirstSpan, ref bytesDecoded, out line))
                        {
                            return (bytesDecoded, line);
                        }
                    }
                    else
                    {
                        foreach (var segment in roSequence)
                        {
                            if (TryDecodeAndFindNewLine(segment.Span, ref bytesDecoded, out line))
                            {
                                return (bytesDecoded, line);
                            }
                        }
                    }
                }

                // At the end, return all remaining chars
                // even when they aren't terminated with a newline.
                if (eof)
                {
                    if (_length > 0)
                    {
                        Span<char> lineSpan = CharsRead;
                        line = lineSpan.ToString();
                        _length = 0;
                    }
                }

                return (bytesDecoded, line);
            }

            private void EnsureSpaceForDecode()
            {
                // Buffer hasn't been allocated yet.
                if (_buffer == null)
                {
                    _buffer = ArrayPool<char>.Shared.Rent(1024);
                    return;
                }

                // Buffer is small compared to a line.
                if (_length * 2 > _buffer!.Length)
                {
                    char[] newBuffer = ArrayPool<char>.Shared.Rent(_length * 2);
                    CharsRead.CopyTo(newBuffer);
                    ArrayPool<char>.Shared.Return(_buffer);
                    _buffer = newBuffer;
                    _offset = 0;
                }
                // Data is past half of the buffer, move it to the front.
                if (_offset * 2 > _buffer.Length)
                {
                    CharsRead.CopyTo(_buffer);
                    _offset = 0;
                }
            }

            private bool TryDecodeAndFindNewLine(ReadOnlySpan<byte> newData, ref int bytesDecoded, out string? line)
            {
                while (!newData.IsEmpty)
                {
                    EnsureSpaceForDecode();

                    // Already decoded.
                    int inspected = _length;

                    // Decpde from newData.
                    Span<char> unused = _buffer.AsSpan(_offset + _length, _buffer!.Length - _offset - _length);
                    _decoder!.Convert(newData, unused, flush: false, out int bytesUsed, out int charsUsed, out bool completed);
                    bytesDecoded += bytesUsed;
                    _length += charsUsed;

                    // Find a newline.
                    if (TryFindNewline(inspected, out line))
                    {
                        return true;
                    }

                    // Strip decoded.
                    newData = newData.Slice(bytesUsed);
                }
                line = null;
                return false;
            }

            private bool TryFindNewline(int inspected, out string? line)
            {
                // Chars separated by '\r', '\n', or '\r\n' are considered newlines.

                // If our last line ended with '\r', skip '\n'.
                if (_skipNewline && _length > 0)
                {
                    _skipNewline = false;

                    if (_buffer![_offset] == '\n')
                    {
                        _offset++;
                        _length--;
                    }
                }

                Span<char> charSpan = CharsRead;
                Span<char> uninspectedSpan = charSpan.Slice(inspected);
                int newlineCharPos = uninspectedSpan.IndexOfAny("\r\n");
                if (newlineCharPos != -1)
                {
                    // Reposition against charSpan.
                    newlineCharPos += inspected;

                    // Find the line.
                    var lineSpan = charSpan.Slice(0, newlineCharPos);
                    line = lineSpan.ToString();

                    // If we end with a '\r', skip '\n' if it is the next char.
                    _skipNewline = charSpan[newlineCharPos] == '\r';

                    int bytesUsed = newlineCharPos + 1;
                    _offset += bytesUsed;
                    _length -= bytesUsed;
                    _mayHaveNewline = true;
                    return true;
                }
                else
                {
                    line = null;
                    return false;
                }
            }
        }

        public int MaxWriteLength => _context.LocalMaxPacketSize;
        public int MaxReadLength => _context.RemoteMaxPacketSize;
        public CancellationToken ChannelAborted => _context.ChannelAborted;
        public CancellationToken ChannelStopped => _context.ChannelStopped;

        private static ProcessReadType StandardOutputEof => (ProcessReadType)(-2);

        internal RemoteProcess(ChannelContext context,
                                Encoding standardInputEncoding,
                                Encoding standardErrorEncoding,
                                Encoding standardOutputEncoding
        )
        {
            _context = context;
            _standardInputEncoding = standardInputEncoding;
            _standardErrorEncoding = standardErrorEncoding;
            _standardOutputEncoding = standardOutputEncoding;
        }

        public int? ExitCode { get; private set; }
        public string? ExitSignal { get; private set; }
        public bool HasExited { get => _exited == 2; private set => _exited = 2; }

        public void Abort(Exception reason)
            => _context.Abort(reason);

        public ValueTask WriteInputAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
            => _context.SendChannelDataAsync(buffer, ct);

        public Stream StandardInputStream
            => StandardInputWriter.BaseStream;

        public StreamWriter StandardInputWriter
            => (_stdInWriter ??= new StreamWriter(new StdInStream(this), _standardInputEncoding));

        public async ValueTask WaitForExitAsync(CancellationToken ct)
        {
            do
            {
                ProcessReadType readResult = await ReceiveUntilProcessReadResultAsync(readStdout: false, readStderr: false, ct);

                if (readResult == ProcessReadType.ProcessExit)
                {
                    HasExited = true;
                    return;
                }

            } while (true);
        }

        public async ValueTask<(string? stdout, string? stderr)> ReadToEndAsStringAsync(bool readStdout = true, bool readStderr = true, CancellationToken ct = default)
        {
            CheckReadState(readStdout, readStderr, ReadStatus.ReadStringToEnd);

            MemoryStream? stdoutStream = readStdout ? new MemoryStream() : null;
            MemoryStream? stderrStream = readStderr ? new MemoryStream() : null;
            await ReadToEndAsync(stdoutStream, stderrStream, disposeStreams: false, ct);
            string? stdout = null;
            if (readStdout)
            {
                stdoutStream!.Position = 0;
                stdout = new StreamReader(stdoutStream, _standardOutputEncoding).ReadToEnd();
            }
            string? stderr = null;
            if (readStderr)
            {
                stderrStream!.Position = 0;
                stderr = new StreamReader(stderrStream, _standardErrorEncoding).ReadToEnd();
            }
            return (stdout, stderr);
        }

        public async ValueTask ReadToEndAsync(Stream? stdoutStream, Stream? stderrStream, bool disposeStreams = true, CancellationToken ct = default)
        {
            try
            {
                await ReadToEndAsync(writeToStream, stdoutStream, writeToStream, stderrStream, ct);
            }
            finally
            {
                if (disposeStreams)
                {
                    if (stdoutStream != null)
                    {
                        await stdoutStream.DisposeAsync();
                    }
                    if (stderrStream != null)
                    {
                        await stderrStream.DisposeAsync();
                    }
                }
            }

            static async ValueTask writeToStream(ReadOnlySequence<byte> data, object? context, CancellationToken ct)
            {
                Stream stream = (Stream)context!;
                if (data.IsSingleSegment)
                {
                    await stream.WriteAsync(data.First, ct);
                }
                else
                {
                    foreach (var segment in data)
                    {
                        await stream.WriteAsync(segment, ct);
                    }
                }
            }
        }

        public async ValueTask ReadToEndAsync(Func<ReadOnlySequence<byte>, object?, CancellationToken, ValueTask>? handleStdout, object? stdoutContext,
                                              Func<ReadOnlySequence<byte>, object?, CancellationToken, ValueTask>? handleStderr, object? stderrContext,
                                              CancellationToken ct = default)
        {
            bool readStdout = handleStdout != null;
            bool readStderr = handleStderr != null;

            CheckReadState(readStdout, readStderr, ReadStatus.ReadRaw);

            do
            {
                try
                {
                    if (_stdoutData != null)
                    {
                        await MoveDataFromSequenceToStreamAsync(_context, _stdoutData, handleStdout, stdoutContext, ct);
                        _stdoutData.Dispose();
                        _stdoutData = null;
                    }

                    if (_stderrData != null)
                    {
                        await MoveDataFromSequenceToStreamAsync(_context, _stderrData, handleStderr, stderrContext, ct);
                        _stderrData.Dispose();
                        _stderrData = null;
                    }
                }
                catch
                {
                    _readStatus = ReadStatus.ReadThrewException;

                    throw;
                }

                ProcessReadType readResult = await ReceiveUntilProcessReadResultAsync(readStdout, readStderr, ct);

                if (readResult == ProcessReadType.ProcessExit)
                {
                    HasExited = true;
                    return;
                }

            } while (true);

            static async ValueTask MoveDataFromSequenceToStreamAsync(ChannelContext context, Sequence sequence,
                Func<ReadOnlySequence<byte>, object?, CancellationToken, ValueTask>? handler, object? handlerContext, CancellationToken ct)
            {
                if (handler != null)
                {
                    await handler(sequence.AsReadOnlySequence(), handlerContext, ct);
                }
                context.AdjustChannelWindow((int)sequence.Length);
            }
        }

        public async ValueTask<(ProcessReadType readType, int bytesRead)> ReadAsync(Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken ct = default)
        {
            bool readStdout = stdoutBuffer != null;
            bool readStderr = stderrBuffer != null;

            if (readStdout && stdoutBuffer!.Value.Length == 0)
            {
                ThrowHelper.ThrowArgumentOutOfRange(nameof(stdoutBuffer));
            }

            if (readStderr && stderrBuffer!.Value.Length == 0)
            {
                ThrowHelper.ThrowArgumentOutOfRange(nameof(stderrBuffer));
            }

            CheckReadState(readStdout, readStderr, ReadStatus.ReadRaw);

            do
            {
                try
                {
                    if (_stdoutData != null)
                    {
                        int length = MoveDataFromSequenceToMemory(_context, ref _stdoutData, stdoutBuffer);
                        if (length != 0)
                        {
                            return (ProcessReadType.StandardOutput, length);
                        }
                    }

                    if (_stderrData != null)
                    {
                        int length = MoveDataFromSequenceToMemory(_context, ref _stderrData, stderrBuffer);
                        if (length != 0)
                        {
                            return (ProcessReadType.StandardError, length);
                        }
                    }
                }
                catch
                {
                    _readStatus = ReadStatus.ReadThrewException;

                    throw;
                }

                ProcessReadType readResult = await ReceiveUntilProcessReadResultAsync(readStdout, readStderr, ct);

                if (readResult == ProcessReadType.ProcessExit)
                {
                    HasExited = true;
                    return (readResult, 0);
                }
                else if (readResult == StandardOutputEof)
                {
                    if (readStdout)
                    {
                        return (ProcessReadType.StandardOutput, 0);
                    }
                }

            } while (true);

            static int MoveDataFromSequenceToMemory(ChannelContext context, ref Sequence? sequence, Memory<byte>? buffer)
            {
                if (buffer != null)
                {
                    int length = length = (int)Math.Min(buffer.Value.Length, sequence!.Length);
                    sequence.AsReadOnlySequence().Slice(0, length).CopyTo(buffer.Value.Span);
                    sequence.Remove(length);
                    if (sequence.IsEmpty)
                    {
                        sequence.Dispose();
                        sequence = null;
                    }
                    context.AdjustChannelWindow(length);
                    return length;
                }
                else
                {
                    context.AdjustChannelWindow((int)sequence!.Length);
                    sequence.Dispose();
                    sequence = null;
                    return 0;
                }
            }
        }

        public async ValueTask<(ProcessReadType readType, string? line)> ReadLineAsync(bool readStdout = true, bool readStderr = true, CancellationToken ct = default)
        {
            CheckReadState(readStdout, readStderr, ReadStatus.ReadLine);

            if (readStdout)
            {
                _stdoutDecoder.Initialize(_standardOutputEncoding);
            }
            if (readStderr)
            {
                _stderrDecoder.Initialize(_standardErrorEncoding);
            }

            do
            {
                try
                {
                    string? line;
                    if (TryReadLine(_context, ref _stdoutData, ref _stdoutDecoder, readStdout, (_exited != 0) || (_stdoutEof != 0), out line))
                    {
                        return (ProcessReadType.StandardOutput, line);
                    }

                    if (TryReadLine(_context, ref _stderrData, ref _stdoutDecoder, readStderr, (_exited != 0), out line))
                    {
                        return (ProcessReadType.StandardError, line);
                    }
                }
                catch
                {
                    _readStatus = ReadStatus.ReadThrewException;

                    throw;
                }

                if (_stdoutEof == 1)
                {
                    _stdoutEof = 2;
                    if (readStdout)
                    {
                        return (ProcessReadType.StandardOutput, null);
                    }
                }

                if (_exited == 1)
                {
                    HasExited = true;
                    return (ProcessReadType.ProcessExit, null);
                }

                await ReceiveUntilProcessReadResultAsync(readStdout, readStderr, ct);

            } while (true);

            static bool TryReadLine(ChannelContext context, ref Sequence? sequence, ref LineDecoder decoder, bool reading, bool eof, out string? line)
            {
                if (reading)
                {
                    int bytesRead;
                    (bytesRead, line) = decoder.TryDecodeLine(sequence, eof);
                    if (bytesRead > 0)
                    {
                        sequence!.Remove(bytesRead);
                        if (sequence.IsEmpty)
                        {
                            sequence.Dispose();
                            sequence = null;
                        }
                        context.AdjustChannelWindow(bytesRead);
                    }
                    return line != null;
                }
                else
                {
                    context.AdjustChannelWindow((int)sequence!.Length);
                    sequence.Dispose();
                    sequence = null;
                    line = null;
                    return false;
                }
            }
        }

        private async ValueTask<ProcessReadType> ReceiveUntilProcessReadResultAsync(bool readStdout, bool readStderr, CancellationToken ct)
        {
            if (_exited > 0)
            {
                return ProcessReadType.ProcessExit;
            }

            do
            {
                using var packet = await _context.ReceivePacketAsync(ct);
                switch (packet.MessageId)
                {
                    case MessageId.SSH_MSG_CHANNEL_DATA:
                        if (readStdout)
                        {
                            _stdoutData = packet.MovePayload();
                            // remove SSH_MSG_CHANNEL_DATA (1), recipient channel (4), and data length (4).
                            _stdoutData.Remove(9);
                            return ProcessReadType.StandardOutput;
                        }
                        break;
                    case MessageId.SSH_MSG_CHANNEL_EXTENDED_DATA:
                        if (readStderr)
                        {
                            /*
                                byte      SSH_MSG_CHANNEL_EXTENDED_DATA
                                uint32    recipient channel
                                uint32    data_type_code
                                string    data
                             */
                            uint data_type_code = ReadDataType(packet);
                            if (data_type_code == SSH_EXTENDED_DATA_STDERR)
                            {
                                _stderrData = packet.MovePayload();
                                // remove SSH_MSG_CHANNEL_EXTENDED_DATA (1), recipient channel (4), data_type_code (4), and data length (4).
                                _stderrData.Remove(13);
                                return ProcessReadType.StandardError;
                            }
                        }
                        break;
                    case MessageId.SSH_MSG_CHANNEL_EOF:
                        _stdoutEof = 1;
                        return StandardOutputEof;
                    case MessageId.SSH_MSG_CHANNEL_CLOSE:
                        _exited = 1;
                        return ProcessReadType.ProcessExit;
                    case MessageId.SSH_MSG_CHANNEL_REQUEST:
                        HandleMsgChannelRequest(packet);
                        break;
                    default:
                        ThrowHelper.ThrowProtocolUnexpectedMessageId(packet.MessageId!.Value);
                        break;
                }
            } while (true);

            static uint ReadDataType(ReadOnlyPacket extendedDataPayload)
            {
                /*
                    byte      SSH_MSG_CHANNEL_EXTENDED_DATA
                    uint32    recipient channel
                    uint32    data_type_code
                    string    data
                */
                var reader = extendedDataPayload.GetReader();
                // skip SSH_MSG_CHANNEL_EXTENDED_DATA, recipient channel
                reader.Skip(5);
                uint data_type_code = reader.ReadUInt32();
                return data_type_code;
            }
        }

        private void HandleMsgChannelRequest(ReadOnlyPacket packet)
        {
            bool want_reply = ParseAndInterpretChannelRequest(packet);
            if (want_reply)
            {
                // If the request is not recognized or is not
                // supported for the channel, SSH_MSG_CHANNEL_FAILURE is returned.

                // Don't await or cancel this.
                ValueTask _ = _context.SendChannelFailureMessageAsync(ct: default);
            }
        }

        private bool ParseAndInterpretChannelRequest(ReadOnlyPacket packet)
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

        public void Dispose()
        {
            _stdoutData?.Dispose();
            _stdoutData = null;

            _stderrData?.Dispose();
            _stderrData = null;

            _stdoutDecoder.Dispose();
            _stderrDecoder.Dispose();

            _context.Dispose();
        }

        private void CheckReadState(bool readStdout, bool readStderr, ReadStatus readMode)
        {
            if (HasExited)
            {
                ThrowHelper.ThrowInvalidOperation("Cannot read after the process has exited.");
            }

            if ((_ignoreStdout && readStdout) ||
                (_ignoreStderr && readStderr))
            {
                ThrowHelper.ThrowInvalidOperation("Cannot read stream after ignoring it.");
            }

            if (_readStatus == ReadStatus.Initial)
            {
                _readStatus = readMode;
            }
            else if (readMode != _readStatus)
            {
                ThrowHelper.ThrowInvalidOperation($"{readMode} not allowed, because previous read was {_readStatus}.");
            }

            _ignoreStdout |= !readStdout;
            _ignoreStderr |= !readStderr;
        }

        sealed class StdInStream : Stream
        {
            private readonly RemoteProcess _process;

            public StdInStream(RemoteProcess process)
            {
                _process = process;
            }

            public override bool CanRead => false;

            public override bool CanSeek => false;

            public override bool CanWrite => true;

            public override long Length => throw new NotSupportedException();

            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public override void Flush()
            { }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            public override Task FlushAsync(CancellationToken cancellationToken)
            {
                return Task.CompletedTask;
            }

            public override ValueTask WriteAsync(System.ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
            {
                return _process.WriteInputAsync(buffer, cancellationToken);
            }
        }
    }
}
