using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

sealed partial class UnixStandardInputReader : IStandardInputReader
{
    const int STDIN_FILENO = 0;
    private readonly Encoding _encoding;
    private readonly Decoder _decoder;
    private readonly Socket _socket;

    public UnixStandardInputReader()
    {
        // By default, Unix terminals are in CANON mode which means they return input line-by-line.
        // .NET disables CANON mode when its reading APIs are used.
        // This makes a cursor position read to disable CANON mode.
        if (!Console.IsInputRedirected)
        {
            _ = Console.CursorTop;
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
    { }
}