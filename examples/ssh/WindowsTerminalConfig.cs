using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static WindowsInterop;

sealed class WindowsTerminalConfig : IDisposable
{
    private const uint EnableStdInFlags = ENABLE_WINDOW_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT;
    private const uint DisableStdInFlags = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT;
    private const uint EnableStdOutFlags = ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
    private const uint DisableStdOutFlags = 0;

    private readonly IntPtr _stdOutHandle;
    private readonly IntPtr _stdInHandle;
    private uint? _originalOutputMode;
    private uint? _originalInputMode;

    private WindowsTerminalConfig()
    {
        _stdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        _stdInHandle = GetStdHandle(STD_INPUT_HANDLE);
    }

    private void ConfigureStandardInput()
    {
        if (!GetConsoleMode(_stdInHandle, out var originalInputMode))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot GetConsoleMode for STD_INPUT_HANDLE.");
        }
        _originalInputMode = originalInputMode;

        var requestedInputMode = (originalInputMode | EnableStdInFlags) & ~DisableStdInFlags;
        if (!SetConsoleMode(_stdInHandle, requestedInputMode))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Cannot SetConsoleMode for STD_INPUT_HANDLE to 0x{requestedInputMode:x}.");
        }
    }

    private void ConfigureStandardOutput()
    {
        if (!GetConsoleMode(_stdOutHandle, out var originalOutputMode))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot GetConsoleMode for STD_OUTPUT_HANDLE.");
        }
        _originalOutputMode = originalOutputMode;

        var requestedOutputMode = (originalOutputMode | EnableStdOutFlags) & ~DisableStdOutFlags;
        if (!SetConsoleMode(_stdOutHandle, requestedOutputMode))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Cannot SetConsoleMode for STD_OUTPUT_HANDLE to 0x{requestedOutputMode:x}.");
        }
    }

    public static WindowsTerminalConfig Configure()
    {
        WindowsTerminalConfig terminalConfig = new();
        try
        {
            terminalConfig.ConfigureStandardInput();
            terminalConfig.ConfigureStandardOutput();

            return terminalConfig;
        }
        catch
        {
            terminalConfig.Dispose();

            throw;
        }
    }

    public void Dispose()
    {
        if (_stdOutHandle != IntPtr.Zero && _originalOutputMode.HasValue)
        {
            SetConsoleMode(_stdOutHandle, _originalOutputMode.Value);
        }

        if (_stdInHandle != IntPtr.Zero && _originalInputMode.HasValue)
        {
            SetConsoleMode(_stdInHandle, _originalInputMode.Value);
        }
    }
}