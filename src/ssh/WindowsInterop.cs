using System;
using System.Runtime.InteropServices;

internal static partial class WindowsInterop
{
    private const string Kernel32 = "kernel32.dll";

    public const uint ENABLE_ECHO_INPUT = 0x0004;
    public const uint ENABLE_INSERT_MODE = 0x0020;
    public const uint ENABLE_LINE_INPUT = 0x0002;
    public const uint ENABLE_MOUSE_INPUT = 0x0010;
    public const uint ENABLE_PROCESSED_INPUT = 0x0001;
    public const uint ENABLE_QUICK_EDIT_MODE = 0x0040;
    public const uint ENABLE_WINDOW_INPUT = 0x0008;
    public const uint ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200;
    public const uint ENABLE_PROCESSED_OUTPUT = 0x0001;
    public const uint ENABLE_WRAP_AT_EOL_OUTPUT = 0x0002;
    public const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;
    public const uint DISABLE_NEWLINE_AUTO_RETURN = 0x0008;
    public const uint ENABLE_LVB_GRID_WORLDWIDE = 0x0010;

    public const int STD_OUTPUT_HANDLE = -11;
    public const int STD_INPUT_HANDLE = -10;

    [LibraryImport(Kernel32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetConsoleMode(IntPtr handle, out uint mode);

    [LibraryImport(Kernel32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetConsoleMode(IntPtr handle, uint mode);

    [LibraryImport(Kernel32, SetLastError = true)]
    public static partial IntPtr GetStdHandle(int handle);

    [LibraryImport(Kernel32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CancelIoEx(IntPtr handle, IntPtr lpOverlapped);

    [LibraryImport(Kernel32, SetLastError = true)]
    public static unsafe partial int ReadFile(
        IntPtr handle,
        byte* bytes,
        int numBytesToRead,
        out int numBytesRead,
        IntPtr mustBeZero);

    public const int KEY_EVENT = 0x1;
    public const int WINDOW_BUFFER_SIZE_EVENT = 0x4;

    [LibraryImport(Kernel32, EntryPoint = "ReadConsoleInputW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public unsafe static partial bool ReadConsoleInput(IntPtr hConsoleInput, INPUT_RECORD* buffer, int length, out int numberOfEventsRead);

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUT_RECORD
    {
        [FieldOffset(0)]
        public ushort EventType;
        [FieldOffset(4)]
        public KEY_EVENT_RECORD KeyEvent;
        [FieldOffset(4)]
        public WINDOW_BUFFER_SIZE_RECORD WindowBufferSizeEvent;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct KEY_EVENT_RECORD
    {
        public int KeyDown;
        public short RepeatCount;
        public short VirtualKeyCode;
        public short VirtualScanCode;
        public char uChar;
        public int ControlKeyState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct COORD
    {
        public short X;
        public short Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WINDOW_BUFFER_SIZE_RECORD
    {
        public COORD Size;
    }
}
