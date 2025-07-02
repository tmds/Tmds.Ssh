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
    private readonly Encoding _encoding;
    private readonly Decoder _decoder;
    private readonly IntPtr _handle;
    private bool _reading;

    public WindowsStandardInputReader()
    {
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

        bool readSuccess;

        _reading = true;
        // Note: this poor man's cancellation may cause characters to get lost.
        //       we don't care about that because the application exists.
        using var ctr = cancellationToken.UnsafeRegister(o => ((WindowsStandardInputReader)o!).CancelIO(), this);
        byte[] bytes = new byte[_encoding.GetMaxByteCount(buffer.Length)];
        int bytesRead;
        fixed (byte* ptr = bytes)
        {
            readSuccess = (0 != ReadFile(_handle, ptr, buffer.Length, out bytesRead, IntPtr.Zero));
        }
        _reading = false;

        if (readSuccess)
        {
            _decoder.Convert(bytes.AsSpan(0, bytesRead), buffer.Span, flush: false, out int bytesUsed, out int charsUsed, out bool completed);
            Debug.Assert(bytesRead == bytesUsed);
            return charsUsed;
        }
        else
        {
            cancellationToken.ThrowIfCancellationRequested();

            int errorCode = Marshal.GetLastPInvokeError();
            throw new Win32Exception(errorCode);
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
    { }
}
