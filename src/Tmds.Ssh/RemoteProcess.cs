// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace Tmds.Ssh;

/// <summary>
/// Represents a remote process.
/// </summary>
public sealed class RemoteProcess : IDisposable
{
    enum ProcessReadType
    {
        StandardOutput = 1,
        StandardError = 2,
        ProcessExit = 3,
    }

    internal const int BufferSize = 1024;

    private readonly ISshChannel _channel;
    private readonly Encoding _standardInputEncoding;
    private readonly Encoding _standardErrorEncoding;
    private readonly Encoding _standardOutputEncoding;
    private readonly bool _hasTty;
    private StreamWriter? _stdInWriter;
    private byte[]? _byteBuffer;

    internal struct CharBuffer
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

        public void AppendFromEncoded(ReadOnlySpan<byte> buffer)
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

        public bool TryReadLine(out ReadOnlyMemory<char> line, bool final)
        {
            line = default;
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
                        line = GetStringBuilderMemoryAndClear(_sb);
                    }
                    else
                    {
                        line = _charBuffer.AsMemory(_charPos, idx);
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

        public bool TryReadLine(out string? line, bool final)
        {
            if (TryReadLine(out ReadOnlyMemory<char> memory, final))
            {
                line = memory.ToString();
                return true;
            }
            line = null;
            return false;
        }

        public ReadOnlyMemory<char> BuildString()
        {
            ReadOnlyMemory<char> s;
            if (_sb is { Length: > 0 })
            {
                AppendCharsToStringBuilder();
                s = GetStringBuilderMemoryAndClear(_sb);
            }
            else if (_charBuffer == null)
            {
                s = default;
            }
            else
            {
                s = _charBuffer.AsMemory(_charPos, _charLen - _charPos);
                _charLen = _charPos = 0;
            }
            return s;
        }

        private static ReadOnlyMemory<char> GetStringBuilderMemoryAndClear(StringBuilder sb)
        {
            var enumerator = sb.GetChunks().GetEnumerator();
            if (enumerator.MoveNext())
            {
                ReadOnlyMemory<char> firstChunk = enumerator.Current;
                if (!enumerator.MoveNext())
                {
                    // Single chunk - return memory directly
                    sb.Clear();
                    return firstChunk;
                }
            }

            ReadOnlyMemory<char> s = sb.ToString().AsMemory();
            sb.Clear();
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

    /// <summary>
    /// Returns the exit code of the process.
    /// </summary>
    public int ExitCode
    {
        get
        {
            EnsureExited();

            return _channel.ExitCode!.Value;
        }
    }

    /// <summary>
    /// Returns the signal that terminated the process when terminated by a signal.
    /// </summary>
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

    /// <summary>
    /// Returns whether the process was started with a terminal.
    /// </summary>
    public bool HasTerminal
    {
        get
        {
            ThrowIfDisposed();

            return _hasTty;
        }
    }

    /// <summary>
    /// Gets a cancellation token that is canceled when execution is aborted.
    /// </summary>
    public CancellationToken ExecutionAborted
        => _channel.ChannelAborted;

    internal enum ReadMode
    {
        Initial,
        ReadBytes,
        ReadChars,
        ReadStream,
        ReadException,
        Exited,
        Disposed
    }

    private ReadMode _readMode;
    private bool _delayedExit;

    internal bool HasExited { get => _readMode == ReadMode.Exited; } // delays exit until it was read by the user.

    internal Encoding StandardErrorEncoding => _standardErrorEncoding;

    internal bool EofSent => _channel.EofSent;

    private void WriteEof(bool noThrow)
    {
        _channel.WriteEof(noThrow);
    }

    /// <summary>
    /// Writes end-of-file to the process standard input.
    /// </summary>
    public void WriteEof()
    {
        WriteEof(noThrow: false);
    }

    /// <summary>
    /// Sets the terminal window size.
    /// </summary>
    /// <param name="width">The terminal width in characters.</param>
    /// <param name="height">The terminal height in characters.</param>
    /// <returns><see langword="true"/> if the size change was sent successfully.</returns>
    public bool SetTerminalSize(int width, int height)
    {
        ThrowIfNotHasTerminal();

        return _channel.ChangeTerminalSize(width, height);
    }

    /// <summary>
    /// Sends a signal to the process.
    /// </summary>
    /// <param name="signalName">The signal name (e.g., "TERM", "KILL").</param>
    /// <returns><see langword="true"/> if the signal was sent successfully.</returns>
    public bool SendSignal(string signalName)
    {
        ThrowIfDisposed();

        return _channel.SendSignal(signalName);
    }

    /// <summary>
    /// Writes bytes to the process standard input.
    /// </summary>
    /// <param name="buffer">The buffer to write.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return _channel.WriteAsync(buffer, cancellationToken);
    }

    /// <summary>
    /// Writes characters to the process standard input.
    /// </summary>
    /// <param name="buffer">The buffer to write.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
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

    /// <summary>
    /// Writes a line of characters to the process standard input.
    /// </summary>
    /// <param name="buffer">The buffer to write.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
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

    /// <summary>
    /// Writes a string to the process standard input.
    /// </summary>
    /// <param name="value">The string to write.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public ValueTask WriteAsync(string value, CancellationToken cancellationToken = default)
        => WriteAsync(value.AsMemory(), cancellationToken);

    /// <summary>
    /// Writes a line of text to the process standard input.
    /// </summary>
    /// <param name="value">The string to write.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public ValueTask WriteLineAsync(string? value, CancellationToken cancellationToken = default)
        => WriteLineAsync(value != null ? value.AsMemory() : default, cancellationToken);

    /// <summary>
    /// Returns a Stream for writing to the process standard input.
    /// </summary>
    public Stream StandardInputStream
        => StandardInputWriter.BaseStream;

    /// <summary>
    /// Returns a StreamWriter for writing to the process standard input.
    /// </summary>
    public StreamWriter StandardInputWriter
    {
        get
        {
            if (_stdInWriter is null)
            {
                // We don't want this property to throw. FakeWritable ensures the StreamWriter doesn't throw for a non-readable stream.
                var stream = new StdInStream(this) { FakeWritable = true };
                var writer = new StreamWriter(stream, _standardInputEncoding) { AutoFlush = true, NewLine = "\n" };
                stream.FakeWritable = false;
                _stdInWriter = writer;
            }
            return _stdInWriter;
        }
    }

    /// <summary>
    /// Reads the process output as a Stream.
    /// </summary>
    /// <param name="stderrHandler"><see cref="StderrHandler"/> for standard error output.</param>
    /// <returns>A <see cref="Stream"/> for reading standard output.</returns>
    public Stream ReadAsStream(StderrHandler stderrHandler)
    {
        CheckReadMode(ReadMode.ReadStream, ensureChange : true);
        StderrHandler.IHandlerInstance? handlerInstance = stderrHandler.CreateInstance(this);
        return new StdOutStream(this, handlerInstance);
    }

    /// <summary>
    /// Reads the process output as a <see cref="StreamReader"/>.
    /// </summary>
    /// <param name="stderrHandler"><see cref="StderrHandler"/> for standard error output.</param>
    /// <param name="bufferSize">Buffer size for the <see cref="StreamReader"/>.</param>
    /// <returns>A <see cref="StreamReader"/> for reading standard output.</returns>
    public StreamReader ReadAsStreamReader(StderrHandler stderrHandler, int bufferSize = -1)
    {
        Stream stream = ReadAsStream(stderrHandler);
        return new StreamReader(stream, _standardOutputEncoding, detectEncodingFromByteOrderMarks: false, bufferSize, leaveOpen: false);
    }

    /// <summary>
    /// Reads process output as bytes.
    /// </summary>
    /// <param name="stdoutBuffer">Buffer for standard output.</param>
    /// <param name="stderrBuffer">Buffer for standard error.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A tuple indicating if data is from stdout or stderr and the amount of bytes read.</returns>
    public ValueTask<(bool isError, int bytesRead)> ReadAsync(Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken cancellationToken = default)
        => ReadAsync(ReadMode.ReadBytes, stdoutBuffer, stderrBuffer, cancellationToken);

    internal async ValueTask<(bool isError, int bytesRead)> ReadAsync(ReadMode readMode, Memory<byte>? stdoutBuffer, Memory<byte>? stderrBuffer, CancellationToken cancellationToken)
    {
        CheckReadMode(readMode);

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

    /// <summary>
    /// Waits for the process to exit.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public ValueTask WaitForExitAsync(CancellationToken cancellationToken = default)
    {
        return ReadToEndAsync(null, null, null, null, cancellationToken);
    }

    /// <summary>
    /// Reads all output until the process exits and returns it as strings.
    /// </summary>
    /// <param name="readStdout">Whether to read standard output.</param>
    /// <param name="readStderr">Whether to read standard error.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A tuple containing stdout and stderr as strings.</returns>
    public async ValueTask<(string stdout, string stderr)> ReadToEndAsStringAsync(bool readStdout = true, bool readStderr = true, CancellationToken cancellationToken = default)
    {
        CheckReadMode(ReadMode.ReadChars);

        while (true)
        {
            ProcessReadType readType = await ReadCharsAsync(readStdout, readStderr, cancellationToken).ConfigureAwait(false); ;
            if (readType == ProcessReadType.ProcessExit)
            {
                _readMode = ReadMode.Exited;
                string stdout = readStdout ? _stdoutBuffer.BuildString().ToString() : "";
                string stderr = readStderr ? _stderrBuffer.BuildString().ToString() : "";
                return (stdout, stderr);
            }
        }
    }

    /// <summary>
    /// Writes all output to <see cref="Stream"/>s until the process exits.
    /// </summary>
    /// <param name="stdoutStream"><see cref="Stream"/> to write standard output to.</param>
    /// <param name="stderrStream"><see cref="Stream"/> to write standard error to.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
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

    /// <summary>
    /// Reads all output until the process exits using custom handlers.
    /// </summary>
    /// <param name="handleStdout">Handler for standard output data.</param>
    /// <param name="stdoutContext">Context passed to the stdout handler.</param>
    /// <param name="handleStderr">Handler for standard error data.</param>
    /// <param name="stderrContext">Context passed to the stderr handler.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
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

    /// <summary>
    /// Reads all lines from the process output asynchronously.
    /// </summary>
    /// <param name="readStdout">Whether to read standard output.</param>
    /// <param name="readStderr">Whether to read standard error.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>An async enumerable of lines with stdout or stderr indicator.</returns>
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

    /// <summary>
    /// Reads a single line from the process output.
    /// </summary>
    /// <param name="readStdout">Whether to read standard output.</param>
    /// <param name="readStderr">Whether to read standard error.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A tuple indicating if the line is from stdout or stderr and the line text.</returns>
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

    /// <summary>
    /// Reads process output as characters.
    /// </summary>
    /// <param name="stdoutBuffer">Buffer for standard output.</param>
    /// <param name="stderrBuffer">Buffer for standard error.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A tuple indicating if data is from stdout or stderr and the amount of characters read.</returns>
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

    /// <summary>
    /// Disposes the SSH channel that executes the process.
    /// </summary>
    public void Dispose()
    {
        _readMode = ReadMode.Disposed;
        _channel.Dispose();
    }

    private void CheckReadMode(ReadMode readMode, bool ensureChange = false)
    {
        if (_readMode == ReadMode.Disposed)
        {
            ObjectDisposedException.ThrowIf(true, this);
        }
        else if (_readMode == ReadMode.Exited)
        {
            throw new InvalidOperationException("The process has exited");
        }
        if (_readMode == ReadMode.ReadException)
        {
            throw new InvalidOperationException("Previous read operation threw an exception.");
        }
        if (readMode == ReadMode.Exited)
        {
            return;
        }

        if (_readMode == ReadMode.ReadChars)
        {
            if (readMode == ReadMode.ReadBytes)
            {
                throw new InvalidOperationException("Cannot read raw bytes after reading chars.");
            }
            else if (readMode == ReadMode.ReadStream)
            {
                throw new InvalidOperationException("Cannot read as stream after reading chars.");
            }
        }
        else if (_readMode == ReadMode.ReadStream && (readMode != ReadMode.ReadStream || ensureChange))
        {
            throw new InvalidOperationException("Stream previously returned for reading must be used.");
        }

        _readMode = readMode;
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

    sealed class StdOutStream : Stream
    {
        private readonly RemoteProcess _process;
        private readonly StderrHandler.IHandlerInstance? _stderrHandler;
        private readonly byte[]? _stderrBuffer;
        private bool _disposed;

        public StdOutStream(RemoteProcess process, StderrHandler.IHandlerInstance? stderrHandler)
        {
            _process = process;
            _stderrHandler = stderrHandler;
            if (_stderrHandler != null)
            {
                // TODO: alloc from ArrayPool?
                _stderrBuffer = new byte[BufferSize];
            }
        }

        public override bool CanRead
        {
            get
            {
                ThrowIfDisposed();
                // We only use properties that are observable by the user to avoid unexpected throwing. HasExited means the user has read the exit.
                return !_process.HasExited;
            }
        }

        public override bool CanSeek
        {
            get
            {
                ThrowIfDisposed();
                return false;
            }
        }

        public override bool CanWrite
        {
            get
            {
                ThrowIfDisposed();
                return false;
            }
        }

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
            // WriteAsync always flushes
        }

        public override Task FlushAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask; // WriteAsync always flushes
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("Synchronous read is not supported. Use ReadAsync instead.");
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

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            // Continue to return zero when eof.
            if (_process.HasExited)
            {
                return 0;
            }

            try
            {
                while (true)
                {
                    Memory<byte>? stderrBuffer = _stderrBuffer != null ? (Memory<byte>?)_stderrBuffer : default(Memory<byte>?);
                    (bool isError, int bytesRead) = await _process.ReadAsync(ReadMode.ReadStream, buffer, stderrBuffer, cancellationToken).ConfigureAwait(false);

                    if (isError)
                    {
                        // Handle stderr data
                        if (_stderrHandler != null && bytesRead > 0)
                        {
                            await _stderrHandler.HandleBufferAsync(_stderrBuffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                        }
                        // Continue reading to get stdout data
                        continue;
                    }
                    else
                    {
                        // Signal end of stream to the stderr handler.
                        if (_stderrHandler != null && bytesRead == 0)
                        {
                            await _stderrHandler.HandleBufferAsync(default, cancellationToken).ConfigureAwait(false);
                        }
                        return bytesRead;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new IOException($"Failed to read from remote process: {ex.Message}", ex);
            }
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return await ReadAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _stderrHandler?.Dispose();
                }
                _disposed = true;
            }
            base.Dispose(disposing);
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
        }
    }

    sealed class StdInStream : Stream
    {
        private readonly RemoteProcess _process;
        internal bool FakeWritable { get; set; }

        public StdInStream(RemoteProcess process)
        {
            _process = process;
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => FakeWritable || !_process.EofSent;

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
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new IOException($"Failed to write to remote process: {ex.Message}", ex);
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
