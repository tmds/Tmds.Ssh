using System;
using System.Buffers;
using System.Collections.Generic;
using System.CommandLine;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

class Program
{
    static Task<int> Main(string[] args)
    {
        var destinationArg = new Argument<string>(name: "destination", () => "localhost")
        { Arity = ArgumentArity.ZeroOrOne };
        var commandArg = new Argument<string>(name: "command", () => "echo 'hello world'")
        { Arity = ArgumentArity.ZeroOrOne };
        var terminalOption = new Option<bool>(new[] { "-t" }, "Allocate a terminal");
        var sshConfigOptions = new Option<string[]>(new[] { "-o", "--option" },
            description: $"Set an SSH Config option, for example: Ciphers=chacha20-poly1305@openssh.com.{Environment.NewLine}Supported options: {string.Join(", ", Enum.GetValues<SshConfigOption>().Select(o => o.ToString()))}.")
        { Arity = ArgumentArity.ZeroOrMore };

        var rootCommand = new RootCommand("Execute a command on a remote system over SSH.");
        rootCommand.AddOption(terminalOption);
        rootCommand.AddOption(sshConfigOptions);
        rootCommand.AddArgument(destinationArg);
        rootCommand.AddArgument(commandArg);
        rootCommand.SetHandler(ExecuteAsync, destinationArg, commandArg, terminalOption, sshConfigOptions);

        return rootCommand.InvokeAsync(args);
    }

    static async Task ExecuteAsync(string destination, string command, bool allocateTerminal, string[] options)
    {
        bool trace = IsEnvvarTrue("TRACE");
        bool log = trace || IsEnvvarTrue("LOG");

        if (allocateTerminal && OperatingSystem.IsWindows())
        {
            // https://github.com/tmds/Tmds.Ssh/pull/376#issuecomment-2696598706
            throw new NotSupportedException("Allocating a terminal is not implemented for Windows.");
        }

        using ILoggerFactory? loggerFactory = !log ? null :
            LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                if (trace)
                {
                    builder.SetMinimumLevel(LogLevel.Trace);
                }
            });

        SshConfigSettings configSettings = CreateSshConfigSettings(options);

        using SshClient client = new SshClient(destination, configSettings, loggerFactory);

        ExecuteOptions? executeOptions = null;
        if (allocateTerminal)
        {
            executeOptions = new()
            {
                AllocateTerminal = true,
                TerminalWidth = Console.WindowWidth,
                TerminalHeight = Console.WindowHeight,
            };
            if (Environment.GetEnvironmentVariable("TERM") is string term)
            {
                executeOptions.TerminalType = term;
            }
        }

        using var process = await client.ExecuteAsync(command, executeOptions);

        using IDisposable? updateWindowSize = allocateTerminal && !Console.IsOutputRedirected ? UpdateTerminalSize(process) : null;
        Task[] tasks = new[]
        {
                PrintToConsole(process),
                ReadInputFromConsole(process)
            };

        Task.WaitAll(tasks);
        PrintExceptions(tasks);

        static async Task PrintToConsole(RemoteProcess process)
        {
            char[] buffer = new char[1024];
            while (true)
            {
                (bool isError, int charsRead) = await process.ReadAsync(buffer, buffer);
                if (charsRead == 0)
                {
                    break;
                }
                TextWriter writer = isError ? Console.Error : Console.Out;
                writer.Write(buffer.AsSpan(0, charsRead));
            }
        }

        static async Task ReadInputFromConsole(RemoteProcess process)
        {
            using IStandardInputReader reader = CreateConsoleInReader();

            char[] buffer = new char[1024];
            try
            {
                while (true)
                {
                    int charsRead = await reader.ReadAsync(buffer, process.ExecutionAborted);
                    if (charsRead == 0)
                    {
                        break;
                    }
                    await process.WriteAsync(buffer.AsMemory(0, charsRead));
                }
                process.WriteEof();
            }
            catch (OperationCanceledException)
            { }
        }

        static void PrintExceptions(Task[] tasks)
        {
            foreach (var task in tasks)
            {
                Exception? innerException = task.Exception?.InnerException;
                if (innerException is not null)
                {
                    Console.WriteLine("Exception:");
                    Console.WriteLine(innerException);
                }
            }
        }
    }

    static IDisposable? UpdateTerminalSize(RemoteProcess process)
    {
        if (OperatingSystem.IsWindows())
        {
            return null;
        }
        else
        {
            return PosixSignalRegistration.Create(PosixSignal.SIGWINCH, ctx => {
                try
                {
                    process.SetTerminalSize(Console.WindowWidth, Console.WindowHeight);
                }
                catch
                { }
            });
        }
    }

    static IStandardInputReader CreateConsoleInReader()
    {
        if (OperatingSystem.IsWindows())
        {
            return new WindowsStandardInputReader();
        }
        else
        {
            return new UnixStandardInputReader();
        }
    }

    private static SshConfigSettings CreateSshConfigSettings(string[] options)
    {
        SshConfigSettings configSettings = new SshConfigSettings();

        Dictionary<SshConfigOption, SshConfigOptionValue> optionsDict = new();
        foreach (var option in options)
        {
            string[] split = option.Split('=', 2);
            if (split.Length != 2)
            {
                throw new ArgumentException($"Option '{option}' is not in the <Key>=<Value> format.");
            }
            if (Enum.TryParse<SshConfigOption>(split[0], ignoreCase: true, out var key))
            {
                optionsDict[key] = split[1];
            }
            else
            {
                throw new ArgumentException($"Unsupported option: {option}.");
            }
        }
        configSettings.Options = optionsDict;

        return configSettings;
    }

    static bool IsEnvvarTrue(string variableName)
    {
        string? value = Environment.GetEnvironmentVariable(variableName);

        if (value is null)
        {
            return false;
        }

        return value == "1";
    }
}

interface IStandardInputReader : IDisposable
{
    ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default);
}

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

sealed partial class WindowsStandardInputReader : IStandardInputReader
{
    private const string Kernel32 = "kernel32.dll";
    private const int STD_INPUT_HANDLE = -10;

    [LibraryImport(Kernel32, SetLastError = true)]
    private static partial IntPtr GetStdHandle(int nStdHandle);

    [LibraryImport(Kernel32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CancelIoEx(IntPtr handle, IntPtr lpOverlapped);

    [LibraryImport(Kernel32, SetLastError = true)]
    internal static unsafe partial int ReadFile(
        IntPtr handle,
        byte* bytes,
        int numBytesToRead,
        out int numBytesRead,
        IntPtr mustBeZero);

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
