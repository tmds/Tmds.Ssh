// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace Tmds.Ssh;

public sealed class RemoteProcess : IDisposable
{
    enum ProcessReadType
    {
        StandardOutput = 1,
        StandardError = 2,
        ProcessExit = 3,
    }

    private const int BufferSize = 1024;

    private readonly ISshChannel _channel;
    private readonly Encoding _standardInputEncoding;
    private readonly Encoding _standardErrorEncoding;
    private readonly Encoding _standardOutputEncoding;
    private readonly bool _hasTty;
    private StreamWriter? _stdInWriter;
    private byte[]? _byteBuffer;

    struct CharBuffer
    {
        public void Initialize(Encoding encoding)
        {
            if (_charBuffer == null)
            {
                // TODO: alloc from ArrayPool?
                _charBuffer = new char[encoding.GetMaxCharCount(BufferSize)];
                _decoder = encoding.GetDecoder();
            }
        }

        public void AppendFromEncoded(Span<byte> buffer)
        {
            if (buffer.Length == 0)
            {
                return;
            }
            int charLength = _charLen - _charPos;
            if (charLength > 0)
            {
                // We only add to the string builder when we're trying to complete a line.
                Debug.Assert(_charBuffer.AsSpan(_charPos, charLength).IndexOfAny('\r', '\n') == -1);

                AppendCharsToStringBuilder();
            }
            _charPos = 0;
            _charLen = _decoder.GetChars(buffer, _charBuffer, flush: false);
            if (_charLen > _charPos && _skipNewlineChar)
            {
                if (_charBuffer[_charPos] == '\n')
                {
                    _charPos++;
                }
                _skipNewlineChar = false;
            }
        }

        private void AppendCharsToStringBuilder()
        {
            int charLength = _charLen - _charPos;
            if (_sb == null)
            {
                _sb = new StringBuilder(charLength + 80);
            }
            _sb.Append(_charBuffer.AsSpan(_charPos, charLength));
            _charPos = _charLen = 0;
        }

        public bool TryReadChars(Memory<char> buffer, out int bytesRead)
        {
            bytesRead = 0;
            if (_charBuffer == null)
            {
                return false;
            }
            int count;
            // Check stringbuilder.
            if (_sb is { Length: > 0 })
            {
                count = Math.Min(_sb.Length, buffer.Length);
                _sb.CopyTo(sourceIndex: 0, buffer.Span, count);
                _sb.Remove(0, count);
                buffer = buffer.Slice(count);
                bytesRead += count;
            }
            // Check chars.
            int charBufferLength = _charLen - _charPos;
            count = Math.Min(charBufferLength, buffer.Length);
            _charBuffer.AsSpan(_charPos, count).CopyTo(buffer.Span);
            _charPos += count;
            bytesRead += count;
            return bytesRead != 0;
        }

        public bool TryReadLine(out string? line, bool final)
        {
            line = null;
            if (_charBuffer == null)
            {
                return false;
            }
            // Check chars.
            if (_charPos != _charLen)
            {
                int idx = _charBuffer.AsSpan(_charPos, _charLen - _charPos).IndexOfAny('\r', '\n');
                if (idx != -1)
                {
                    _skipNewlineChar = _charBuffer[_charPos + idx] == '\r';
                    if (_sb is { Length: > 0 })
                    {
                        _sb.Append(_charBuffer.AsSpan(_charPos, idx));
                        line = _sb.ToString();
                        _sb.Clear();
                    }
                    else
                    {
                        line = new string(_charBuffer.AsSpan(_charPos, idx));
                    }
                    _charPos += idx + 1;
                    if (_skipNewlineChar && _charPos < _charLen)
                    {
                        if (_charBuffer[_charPos] == '\n')
                        {
                            _charPos++;
                        }
                        _skipNewlineChar = false;
                    }
                    return true;
                }
            }
            if (final)
            {
                if (_charPos != _charLen || _sb is { Length: > 0 })
                {
                    line = BuildString();
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                AppendCharsToStringBuilder();
                return false;
            }
        }

        public string? BuildString()
        {
            string? s;
            if (_sb is { Length: > 0 })
            {
                AppendCharsToStringBuilder();
                s = _sb.ToString();
                _sb.Clear();
            }
            else if (_charBuffer == null)
            {
                s = null;
            }
            else
            {
                s = new string(_charBuffer.AsSpan(_charPos, _charLen - _charPos));
                _charLen = _charPos = 0;
            }
            return s;
        }

        private char[] _charBuffer; // Large enough to decode _byteBuffer.
        private Decoder _decoder;
        private int _charPos;
        private int _charLen;
        private StringBuilder? _sb;
        private bool _skipNewlineChar;
    }

    private CharBuffer _stdoutBuffer;
    private CharBuffer _stderrBuffer;

    internal RemoteProcess(ISshChannel channel,
                            Encoding standardInputEncoding,
                            Encoding standardErrorEncoding,
                            Encoding standardOutputEncoding,
                            bool hasTty
    )
    {
        _channel = channel;
        _standardInputEncoding = standardInputEncoding;
        _standardErrorEncoding = standardErrorEncoding;
        _standardOutputEncoding = standardOutputEncoding;
        _hasTty = hasTty;
    }

    public int ExitCode
    {
        get
        {
            EnsureExited();

            return _channel.ExitCode!.Value;
        }
    }

    public string? ExitSignal
    {
        get
        {
            EnsureExited();

            return _channel.ExitSignal;
        }
    }

    private void EnsureExited()
    {
        if (_readMode == ReadMode.Disposed)
        {
            ThrowObjectDisposedException();
        }
        else if (_readMode != ReadMode.Exited)
        {
            throw new InvalidOperationException("The process has not yet exited.");
        }
    }

    public bool HasTerminal
    {
        get
        {
            ThrowIfDisposed();

            return _hasTty;
        }
    }

    public CancellationToken ExecutionAborted
        => _channel.ChannelAborted;

    private enum ReadMode
    {
        Initial,
        ReadBytes,
        ReadChars,
        ReadException,
        Exited,
        Disposed
    }

    private ReadMode _readMode;
    private bool _delayedExit;

    private bool HasExited { get => _readMode == ReadMode.Exited; } // delays exit until it was read by the user.

    private void WriteEof(bool noThrow)
    {
        _channel.WriteEof(noThrow);
    }

    public void WriteEof()
    {
        WriteEof(noThrow: false);
    }

    public bool SetTerminalSize(int width, int height)
    {
        ThrowIfNotHasTerminal();

        return _channel.ChangeTerminalSize(width, height);
    }

    public bool SendSignal(string signalName)
    {
        ThrowIfDisposed();

        return _channel.SendSignal(signalName);
    }

    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return _channel.WriteAsync(buffer, cancellationToken);
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default)
    {
        var writer = StandardInputWriter;
        var autoFlush = writer.AutoFlush;
        if (!autoFlush)
        {
            writer.AutoFlush = true;
        }
        try
        {
            await writer.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        catch (IOException e) // Unwrap IOException. TODO: avoid wrap and unwrap...
        {
            Debug.Assert(e.InnerException != null);
            throw e.InnerException;
        }
        finally
        {
            if (!autoFlush)
            {
                writer.AutoFlush = false;
            }
        }
    }

    public async ValueTask WriteLineAsync(ReadOnlyMemory<char> buffer = default, CancellationToken cancellationToken = default)
    {
        var writer = StandardInputWriter;
        var autoFlush = writer.AutoFlush;
        if (!autoFlush)
        {
            writer.AutoFlush = true;
        }
        try
        {
            await writer.WriteLineAsync(buffer, cancellationToken).ConfigureAwait(false); ;
        }
        catch (IOException e) // Unwrap IOException.
        {
            Debug.Assert(e.InnerException != null);
            throw e.InnerException;
        }
        finally
        {
            if (!autoFlush)
            {
                writer.AutoFlush = false;
            }
        }
    }

    public ValueTask WriteAsync(string value, CancellationToken cancellationToken = default)
        => WriteAsync(value.AsMemory(), cancellationToken);

    public ValueTask WriteLineAsync(string? value, CancellationToken cancellationToken = default)
        => WriteLineAsync(value != null ? value.AsMemory() : default, cancellationToken);

    public Stream StandardInputStream
        => StandardInputWriter.BaseStream;

    public StreamWriter StandardInputWriter
        => _stdInWriter ??= new StreamWriter(new StdInStream(this), _standardInputEncoding) { AutoFlush = true, NewLine = "\n" };

    public async ValueTask<(bool isError, int bytesRead)> ReadAsync(Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken cancellationToken = default)
    {
        CheckReadMode(ReadMode.ReadBytes);

        while (true)
        {
            (ChannelReadType ReadType, int BytesRead) = await _channel.ReadAsync(stdoutBuffer, stderrBuffer, cancellationToken).ConfigureAwait(false); ;
            switch (ReadType)
            {
                case ChannelReadType.StandardOutput:
                    return (false, BytesRead);
                case ChannelReadType.StandardError:
                    return (true, BytesRead);
                case ChannelReadType.Closed:
                    _readMode = ReadMode.Exited;
                    return (false, 0);
                case ChannelReadType.Eof:
                    continue;
                default:
                    throw new IndexOutOfRangeException($"Unexpected read type: {ReadType}.");
            }
        }
    }

    public ValueTask WaitForExitAsync(CancellationToken cancellationToken = default)
    {
        return ReadToEndAsync(null, null, null, null, cancellationToken);
    }

    public async ValueTask<(string stdout, string stderr)> ReadToEndAsStringAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default)
    {
        CheckReadMode(ReadMode.ReadChars);

        while (true)
        {
            ProcessReadType readType = await ReadCharsAsync(readStdout, readStderr, cancellationToken).ConfigureAwait(false); ;
            if (readType == ProcessReadType.ProcessExit)
            {
                _readMode = ReadMode.Exited;
                string stdout = readStdout ? _stdoutBuffer.BuildString()! : "";
                string stderr = readStderr ? _stderrBuffer.BuildString()! : "";
                return (stdout, stderr);
            }
        }
    }

    public async ValueTask ReadToEndAsync(Stream? stdoutStream, Stream? stderrStream, CancellationToken cancellationToken = default)
    {
        await ReadToEndAsync(stdoutStream != null ? writeToStream : null, stdoutStream,
                             stderrStream != null ? writeToStream : null, stderrStream,
                             cancellationToken).ConfigureAwait(false);

        if (stdoutStream != null)
        {
            await stdoutStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        if (stderrStream != null && stderrStream != stdoutStream)
        {
            await stderrStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        static async ValueTask writeToStream(Memory<byte> buffer, object? context, CancellationToken ct)
        {
            Stream stream = (Stream)context!;
            await stream.WriteAsync(buffer, ct).ConfigureAwait(false);
        }
    }

    public async ValueTask ReadToEndAsync(Func<Memory<byte>, object?, CancellationToken, ValueTask>? handleStdout, object? stdoutContext,
                                          Func<Memory<byte>, object?, CancellationToken, ValueTask>? handleStderr, object? stderrContext,
                                          CancellationToken cancellationToken = default)
    {
        ReadMode readMode = handleStdout is null && handleStderr is null ? ReadMode.Exited : ReadMode.ReadBytes;
        CheckReadMode(readMode);

        bool readStdout = handleStdout != null;
        bool readStderr = handleStderr != null;
        byte[]? buffer = ArrayPool<byte>.Shared.Rent(4096);
        Memory<byte>? stdoutBuffer = readStdout ? buffer : default(Memory<byte>?);
        Memory<byte>? stderrBuffer = readStderr ? buffer : default(Memory<byte>?);

        try
        {
            do
            {
                (ChannelReadType readType, int bytesRead) = await _channel.ReadAsync(stdoutBuffer, stderrBuffer, cancellationToken).ConfigureAwait(false); ;
                if (readType == ChannelReadType.StandardOutput)
                {
                    await handleStdout!(stdoutBuffer!.Value.Slice(0, bytesRead), stdoutContext, cancellationToken).ConfigureAwait(false);
                }
                else if (readType == ChannelReadType.StandardError)
                {
                    await handleStderr!(stderrBuffer!.Value.Slice(0, bytesRead), stderrContext, cancellationToken).ConfigureAwait(false);
                }
                else if (readType == ChannelReadType.Closed)
                {
                    _readMode = ReadMode.Exited;
                    return;
                }
            } while (true);
        }
        catch
        {
            _readMode = ReadMode.ReadException;

            throw;
        }
        finally
        {
            if (buffer != null)
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    public async IAsyncEnumerable<(bool isError, string line)> ReadAllLinesAsync(bool readStdout = true, bool readStderr = true, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        while (true)
        {
            (bool isError, string? line) = await ReadLineAsync(readStdout, readStderr, cancellationToken).ConfigureAwait(false); ;
            if (line == null)
            {
                break;
            }
            yield return (isError, line);
        }
    }

    public async ValueTask<(bool isError, string? line)> ReadLineAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default)
    {
        CheckReadMode(ReadMode.ReadChars);

        string? line;
        if (readStdout && _stdoutBuffer.TryReadLine(out line, false))
        {
            return (false, line);
        }
        if (readStderr && _stderrBuffer.TryReadLine(out line, false))
        {
            return (true, line);
        }
        while (true)
        {
            ProcessReadType readType = await ReadCharsAsync(readStdout, readStderr, cancellationToken).ConfigureAwait(false); ;
            if (readType == ProcessReadType.StandardOutput)
            {
                if (_stdoutBuffer.TryReadLine(out line, false))
                {
                    return (false, line);
                }
            }
            else if (readType == ProcessReadType.StandardError)
            {
                if (_stderrBuffer.TryReadLine(out line, false))
                {
                    return (true, line);
                }
            }
            else if (readType == ProcessReadType.ProcessExit)
            {
                if (!_delayedExit)
                {
                    if (readStdout && _stdoutBuffer.TryReadLine(out line, true))
                    {
                        _delayedExit = true;
                        return (false, line);
                    }
                    if (readStderr && _stderrBuffer.TryReadLine(out line, true))
                    {
                        _delayedExit = true;
                        return (true, line);
                    }
                }
                _readMode = ReadMode.Exited;
                return (false, null);
            }
        }
    }

    public async ValueTask<(bool isError, int bytesRead)> ReadAsync(Memory<char>? stdoutBuffer, Memory<char>? stderrBuffer, CancellationToken cancellationToken = default)
    {
        if (stdoutBuffer is { Length: 0 })
        {
            throw new ArgumentException("Buffer length cannot be zero.", nameof(stdoutBuffer));
        }
        if (stderrBuffer is { Length: 0 })
        {
            throw new ArgumentException("Buffer length cannot be zero.", nameof(stderrBuffer));
        }

        CheckReadMode(ReadMode.ReadChars);

        bool readStdout = stdoutBuffer.HasValue;
        bool readStderr = stderrBuffer.HasValue;

        int bytesRead;
        if (readStdout && _stdoutBuffer.TryReadChars(stdoutBuffer!.Value, out bytesRead))
        {
            return (false, bytesRead);
        }
        if (readStderr && _stderrBuffer.TryReadChars(stderrBuffer!.Value, out bytesRead))
        {
            return (true, bytesRead);
        }
        while (true)
        {
            ProcessReadType readType = await ReadCharsAsync(readStdout, readStderr, cancellationToken).ConfigureAwait(false); ;
            if (readType == ProcessReadType.StandardOutput)
            {
                if (_stdoutBuffer.TryReadChars(stdoutBuffer!.Value, out bytesRead))
                {
                    return (false, bytesRead);
                }
            }
            else if (readType == ProcessReadType.StandardError)
            {
                if (_stderrBuffer.TryReadChars(stderrBuffer!.Value, out bytesRead))
                {
                    return (true, bytesRead);
                }
            }
            else if (readType == ProcessReadType.ProcessExit)
            {
                _readMode = ReadMode.Exited;
                return (false, 0);
            }
        }
    }

    private async ValueTask<ProcessReadType> ReadCharsAsync(bool readStdout, bool readStderr, CancellationToken cancellationToken)
    {
        if (_delayedExit)
        {
            return ProcessReadType.ProcessExit;
        }

        if (_byteBuffer == null)
        {
            // TODO: alloc from ArrayPool?
            _byteBuffer = new byte[BufferSize];
            if (readStdout)
            {
                _stdoutBuffer.Initialize(_standardOutputEncoding);
            }
            if (readStderr)
            {
                _stderrBuffer.Initialize(_standardErrorEncoding);
            }
        }
        (ChannelReadType readType, int bytesRead) = await _channel.ReadAsync(readStdout ? _byteBuffer : default(Memory<byte>?),
                                                                             readStderr ? _byteBuffer : default(Memory<byte>?), cancellationToken)
                                                                             .ConfigureAwait(false); ;
        switch (readType)
        {
            case ChannelReadType.StandardOutput:
                _stdoutBuffer.AppendFromEncoded(_byteBuffer.AsSpan(0, bytesRead));
                return ProcessReadType.StandardOutput;
            case ChannelReadType.StandardError:
                _stderrBuffer.AppendFromEncoded(_byteBuffer.AsSpan(0, bytesRead));
                return ProcessReadType.StandardError;
            case ChannelReadType.Eof:
                return await ReadCharsAsync(readStdout, readStderr, cancellationToken)
                    .ConfigureAwait(false); // TODO: remove await, add while loop...
            case ChannelReadType.Closed:
                return ProcessReadType.ProcessExit;
            default:
                throw new InvalidOperationException($"Unknown type: {readType}.");
        }
    }

    public void Dispose()
    {
        _readMode = ReadMode.Disposed;
        _channel.Dispose();
    }

    private void CheckReadMode(ReadMode readMode)
    {
        if (_readMode == ReadMode.Disposed)
        {
            ObjectDisposedException.ThrowIf(true, this);
        }
        else if (_readMode == ReadMode.Exited)
        {
            throw new InvalidOperationException("The process has exited");
        }
        else if (_readMode == ReadMode.ReadException && readMode != ReadMode.Exited)
        {
            throw new InvalidOperationException("Previous read operation threw an exception.");
        }
        else if (_readMode == ReadMode.ReadChars && readMode == ReadMode.ReadBytes)
        {
            throw new InvalidOperationException("Cannot read raw bytes after reading chars.");
        }
        if (_readMode != ReadMode.Exited)
        {
            _readMode = readMode;
        }
    }

    private void ThrowIfDisposed()
    {
        if (_readMode == ReadMode.Disposed)
        {
            ThrowObjectDisposedException();
        }
    }

    private void ThrowIfNotHasTerminal()
    {
        if (!HasTerminal)
        {
            throw new InvalidOperationException("Process was not started with a terminal.");
        }
    }

    private void ThrowObjectDisposedException()
    {
        ObjectDisposedException.ThrowIf(true, this);
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

        public override Task FlushAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask; // WriteAsync always flushes.
        }

        public async override ValueTask WriteAsync(System.ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
        {
            try
            {
                await _process.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            catch (SshException ex)
            {
                throw new IOException($"Unable to transport data: {ex.Message}.", ex);
            }

        }

        public override void Close()
        {
            // The base Stream class calls Close for implementing Dispose.
            // We mustn't throw to avoid throwing on Dispose.
            _process.WriteEof(noThrow: true);
        }
    }
}
