using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static WindowsInterop;

sealed class WindowsConsoleModeConfig : IDisposable
{
    private readonly int _handle;
    private uint? _originalMode;

    private WindowsConsoleModeConfig(int handle)
    {
        _handle = handle;
    }

    private void Configure(uint enableMak, uint disableMask = 0)
    {
        IntPtr handle = GetStdHandle(_handle);
        if (!GetConsoleMode(handle, out var originalMode))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Cannot GetConsoleMode for handle {_handle}.");
        }
        _originalMode = originalMode;

        var requestedInputMode = (originalMode | enableMak) & ~disableMask;
        if (!SetConsoleMode(handle, requestedInputMode))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Cannot SetConsoleMode for handle {_handle} to 0x{requestedInputMode:x}.");
        }
    }

    public static WindowsConsoleModeConfig Configure(int handle, uint enableMak, uint disableMask)
    {
        WindowsConsoleModeConfig terminalConfig = new(handle);
        try
        {
            terminalConfig.Configure(enableMak, disableMask);

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
        if (_originalMode.HasValue)
        {
            SetConsoleMode(GetStdHandle(_handle), _originalMode.Value);
        }
    }
}