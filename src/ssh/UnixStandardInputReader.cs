using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

sealed partial class UnixStandardInputReader : IStandardInputReader
{
    const int STDIN_FILENO = 0;
    private readonly Encoding _encoding;
    private readonly Decoder _decoder;
    private readonly Socket _socket;
    private readonly IDisposable? _sigWinchHandler;
    private Action<int, int>? _windowSizeChanged;

    public event Action<int, int>? WindowSizeChanged
    {
        add
        {
            _windowSizeChanged += value;

            if (_sigWinchHandler is not null)
            {
                value?.Invoke(Console.WindowWidth, Console.WindowHeight);
            }
        }
        remove
        {
            _windowSizeChanged -= value;
        }
    }

    private void EmitWindowSizeChanged(int width, int height)
    {
        _windowSizeChanged?.Invoke(width, height);
    }

    public UnixStandardInputReader(bool forTerminal)
    {
        if (!Console.IsInputRedirected)
        {
            if (forTerminal)
            {
                // By default, Unix terminals are in CANON mode which means they return input line-by-line.
                // .NET disables CANON mode when its reading APIs are used.
                // This makes a cursor position read to disable CANON mode.
                _ = Console.CursorTop;
                Console.TreatControlCAsInput = true;

                // Register for window size changed.
                _sigWinchHandler = PosixSignalRegistration.Create(PosixSignal.SIGWINCH, ctx => EmitWindowSizeChanged(Console.WindowWidth, Console.WindowHeight));
            }
        }

        _encoding = Console.InputEncoding;
        _decoder = Console.InputEncoding.GetDecoder();
        // Directly read stdin so that the Console does not interpret the terminal sequences and we can send them as read.
        SafeSocketHandle handle = new SafeSocketHandle(new IntPtr(STDIN_FILENO), ownsHandle: false);
        // Use a Socket since that supports cancellable async I/O on various handles (on Unix).
        _socket = new Socket(handle);
    }

    public async ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default)
    {
        byte[] bytes = new byte[_encoding.GetMaxByteCount(buffer.Length)];
        int bytesRead = await _socket.ReceiveAsync(bytes, cancellationToken);
        _decoder.Convert(bytes.AsSpan(0, bytesRead), buffer.Span, flush: false, out int bytesUsed, out int charsUsed, out bool completed);
        Debug.Assert(bytesRead == bytesUsed);
        return charsUsed;
    }

    public void Dispose()
    {
        _sigWinchHandler?.Dispose();
    }
}