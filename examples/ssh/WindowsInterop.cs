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

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetConsoleMode(IntPtr handle, out uint mode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetConsoleMode(IntPtr handle, uint mode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial IntPtr GetStdHandle(int handle);

    [LibraryImport(Kernel32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CancelIoEx(IntPtr handle, IntPtr lpOverlapped);

    [LibraryImport(Kernel32, SetLastError = true)]
    internal static unsafe partial int ReadFile(
        IntPtr handle,
        byte* bytes,
        int numBytesToRead,
        out int numBytesRead,
        IntPtr mustBeZero);
}
