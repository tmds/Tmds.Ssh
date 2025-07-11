using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static WindowsInterop;

sealed class WindowsStandardInputReader : IStandardInputReader
{
    private const uint TerminalEnableStdInFlags = ENABLE_WINDOW_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT;
    private const uint TerminalDisableStdInFlags = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT;
    private const uint NoTerminalEnableStdInFlags = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
    private const uint NoTerminalDisableStdInFlags = 0;

    private readonly Encoding _encoding;
    private readonly Decoder _decoder;
    private readonly IntPtr _handle;
    private readonly WindowsConsoleModeConfig? _stdInConfig;
    private bool _reading;
    private bool _convertLineEndings;
    private bool _readConsole;
    private Action<int, int>? _windowSizeChanged;

    public event Action<int, int>? WindowSizeChanged
    {
        add
        {
            _windowSizeChanged += value;
            if (_readConsole)
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

    public WindowsStandardInputReader(bool forTerminal)
    {
        if (!Console.IsInputRedirected)
        {
            _stdInConfig = forTerminal ? WindowsConsoleModeConfig.Configure(STD_INPUT_HANDLE, TerminalEnableStdInFlags, TerminalDisableStdInFlags)
                                       : WindowsConsoleModeConfig.Configure(STD_INPUT_HANDLE, NoTerminalEnableStdInFlags, NoTerminalDisableStdInFlags);
            _convertLineEndings = !forTerminal;
            _readConsole = forTerminal;
        }

        _handle = GetStdHandle(STD_INPUT_HANDLE);
        _encoding = Console.InputEncoding;
        _decoder = Console.InputEncoding.GetDecoder();
    }

    public async ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default)
    {
        // Yield to avoid blocking.
        await Task.Yield();

        // This blocks but it respects the cancellation token.
        return Read(buffer, cancellationToken);
    }

    private unsafe int Read(Memory<char> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _reading = true;
        // Note: this poor man's cancellation may cause characters to get lost.
        //       we don't care about that because the application exists.
        using var ctr = cancellationToken.UnsafeRegister(o => ((WindowsStandardInputReader)o!).CancelIO(), this);
        int charsWritten = _readConsole ? ReadConsole(_handle, buffer.Span) : Readfile(_handle, buffer);
        _reading = false;

        if (charsWritten == -1)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int errorCode = Marshal.GetLastPInvokeError();
            throw new Win32Exception(errorCode);
        }

        return charsWritten;
    }

    private unsafe int Readfile(IntPtr hConsoleInput, Memory<char> buffer)
    {
        byte[] bytes = new byte[_encoding.GetMaxByteCount(buffer.Length)];
        int bytesRead;
        fixed (byte* ptr = bytes)
        {
            bool readSuccess = 0 != ReadFile(_handle, ptr, buffer.Length, out bytesRead, IntPtr.Zero);
            if (!readSuccess)
            {
                return -1;
            }
        }
        Span<byte> bytesReadSpan = bytes.AsSpan(0, bytesRead);
        if (_convertLineEndings)
        {
            if (bytesReadSpan.EndsWith("\r\n"u8))
            {
                bytesReadSpan = bytesReadSpan[..^1];
                bytesReadSpan[^1] = (byte)'\n';
            }
            else if (bytesReadSpan.EndsWith("\r"u8))
            {
                bytesReadSpan[^1] = (byte)'\n';
            }
        }
        _decoder.Convert(bytesReadSpan, buffer.Span, flush: false, out int bytesUsed, out int charsRead, out bool completed);
        Debug.Assert(bytesReadSpan.Length == bytesUsed);
        return charsRead;
    }

    private unsafe int ReadConsole(IntPtr hConsoleInput, Span<char> buffer)
    {
        Span<INPUT_RECORD> inputRecords = stackalloc INPUT_RECORD[Math.Min(buffer.Length, 1024)];
        while (true)
        {
            int numEventsRead;
            fixed (INPUT_RECORD* ptr = inputRecords)
            {
                bool readSuccess = ReadConsoleInput(_handle, ptr, inputRecords.Length, out numEventsRead);
                if (!readSuccess)
                {
                    return -1;
                }
            }

            int charsWritten = 0;
            foreach (INPUT_RECORD record in inputRecords.Slice(0, numEventsRead))
            {
                switch (record.EventType)
                {
                    case KEY_EVENT:
                        if (record.KeyEvent.KeyDown != 0 && record.KeyEvent.uChar != 0)
                        {
                            buffer[charsWritten++] = record.KeyEvent.uChar;
                        }
                        break;
                    case WINDOW_BUFFER_SIZE_EVENT:
                        EmitWindowSizeChanged(record.WindowBufferSizeEvent.Size.X, record.WindowBufferSizeEvent.Size.Y);
                        break;
                }
            }

            if (charsWritten > 0)
            {
                return charsWritten;
            }
        }
    }

    private void CancelIO()
    {
        // Loop in case we get cancelled before ReadConsole got called.
        while (_reading)
        {
            CancelIoEx(_handle, IntPtr.Zero);
            Thread.Sleep(10);
        }
    }

    public void Dispose()
    {
        _stdInConfig?.Dispose();
    }
}
