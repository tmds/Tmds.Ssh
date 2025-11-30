// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public readonly struct StderrHandler
{
    private readonly Func<RemoteProcess, object, object?, IHandlerInstance> _factory;
    private readonly object _handler;
    private readonly object? _context;

    public static StderrHandler Ignore => default;

    public StderrHandler(Func<ReadOnlyMemory<byte>, object?, CancellationToken, ValueTask> handler, object? context = null)
    {
        _factory = CreateInstanceForFuncOfByte;
        _handler = handler;
        _context = context;
    }

    public StderrHandler(Stream stream)
        : this((buffer, context, cancellationToken) => ((Stream)context!).WriteAsync(buffer, cancellationToken), stream)
    { }

    public static implicit operator StderrHandler(Stream stream) => new StderrHandler(stream);

    public StderrHandler(Func<ReadOnlyMemory<char>, object?, CancellationToken, ValueTask> handler, bool lineByLine, object? context = null)
    {
        _factory = lineByLine ? CreateInstanceForFuncOfCharLineByLine : CreateInstanceForFuncOfChar;
        _handler = handler;
        _context = context;
    }

    public StderrHandler(System.Text.StringBuilder stringBuilder)
        : this(AppendCharsToStringBuilder, lineByLine: false, stringBuilder)
    {
    }

    public static implicit operator StderrHandler(System.Text.StringBuilder stringBuilder) => new StderrHandler(stringBuilder);

    private static ValueTask AppendCharsToStringBuilder(ReadOnlyMemory<char> buffer, object? context, CancellationToken _)
    {
        System.Text.StringBuilder sb = (System.Text.StringBuilder)context!;
        sb.Append(buffer.Span);
        return default;
    }

    internal IHandlerInstance? CreateInstance(RemoteProcess process)
    {
        return _factory?.Invoke(process, _handler, _context);
    }

    private static IHandlerInstance CreateInstanceForFuncOfByte(RemoteProcess process, object handler, object? context)
    {
        var func = (Func<ReadOnlyMemory<byte>, object?, CancellationToken, ValueTask>)handler;
        return new FuncOfMemoryHandler(func, context);
    }

    private static IHandlerInstance CreateInstanceForFuncOfChar(RemoteProcess process, object handler, object? context)
    {
        var func = (Func<ReadOnlyMemory<char>, object?, CancellationToken, ValueTask>)handler;
        return new FuncOfCharHandler(func, context, process);
    }

    private static IHandlerInstance CreateInstanceForFuncOfCharLineByLine(RemoteProcess process, object handler, object? context)
    {
        var func = (Func<ReadOnlyMemory<char>, object?, CancellationToken, ValueTask>)handler;
        return new FuncOfCharLineByLineHandler(func, context, process);
    }

    private sealed class FuncOfMemoryHandler(Func<ReadOnlyMemory<byte>, object?, CancellationToken, ValueTask> handler, object? context) : IHandlerInstance
    {
        public ValueTask HandleBufferAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            return handler(buffer, context, cancellationToken);
        }

        public void Dispose()
        { }
    }

    private sealed class FuncOfCharHandler : IHandlerInstance
    {
        private readonly Func<ReadOnlyMemory<char>, object?, CancellationToken, ValueTask> _handler;
        private readonly object? _context;
        private readonly System.Text.Decoder _decoder;
        private readonly char[] _charBuffer;

        public FuncOfCharHandler(Func<ReadOnlyMemory<char>, object?, CancellationToken, ValueTask> handler, object? context, RemoteProcess process)
        {
            _handler = handler;
            _context = context;
            var encoding = process.StandardErrorEncoding;
            _decoder = encoding.GetDecoder();
            _charBuffer = new char[encoding.GetMaxCharCount(RemoteProcess.BufferSize)];
        }

        public async ValueTask HandleBufferAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            bool isEnd = buffer.Length == 0;

            int charCount = _decoder.GetChars(buffer.Span, _charBuffer, flush: isEnd);
            if (charCount > 0)
            {
                await _handler(_charBuffer.AsMemory(0, charCount), _context, cancellationToken).ConfigureAwait(false);
            }
        }

        public void Dispose()
        { }
    }

    private sealed class FuncOfCharLineByLineHandler : IHandlerInstance
    {
        private readonly Func<ReadOnlyMemory<char>, object?, CancellationToken, ValueTask> _handler;
        private readonly object? _context;
        private RemoteProcess.CharBuffer _charBuffer;

        public FuncOfCharLineByLineHandler(Func<ReadOnlyMemory<char>, object?, CancellationToken, ValueTask> handler, object? context, RemoteProcess process)
        {
            _handler = handler;
            _context = context;
            _charBuffer = new RemoteProcess.CharBuffer();
            _charBuffer.Initialize(process.StandardErrorEncoding);
        }

        public async ValueTask HandleBufferAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            bool isEnd = buffer.Length == 0;

            if (!isEnd)
            {
                _charBuffer.AppendFromEncoded(buffer.Span);
            }

            // Read all available complete lines
            while (_charBuffer.TryReadLine(out ReadOnlyMemory<char> line, isEnd))
            {
                await _handler(line, _context, cancellationToken).ConfigureAwait(false);
            }
        }

        public void Dispose()
        { }
    }

    internal interface IHandlerInstance
    {
        ValueTask HandleBufferAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken);
        void Dispose();
    }
}
