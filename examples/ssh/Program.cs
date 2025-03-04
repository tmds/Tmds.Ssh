using System;
using System.Collections.Generic;
using System.CommandLine;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

namespace Tmds.Ssh;

class Program
{
    static Task<int> Main(string[] args)
    {
        var destinationArg = new Argument<string>(name: "destination", () => "localhost")
        { Arity = ArgumentArity.ZeroOrOne };
        var commandArg = new Argument<string>(name: "command", () => "echo 'hello world'")
        { Arity = ArgumentArity.ZeroOrOne };
        var terminalOption = new Option<bool>(new[] { "-t"}, "Allocate a terminal");
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
        if (OperatingSystem.IsWindows() && allocateTerminal)
        {
            Console.Error.WriteLine("Allocating a terminal is not implemented for Windows.");
            allocateTerminal = false; 
        }

        bool trace = IsEnvvarTrue("TRACE");
        bool log = trace || IsEnvvarTrue("LOG");

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
                TerminalHeight = Console.WindowHeight,
                TerminalWidth = Console.WindowWidth
            };
            if (Environment.GetEnvironmentVariable("TERM") is string term)
            {
                executeOptions.TerminalType = term;
            }
        }

        using var process = await client.ExecuteAsync(command, executeOptions);
        Task[] tasks = new[]
        {
                PrintToConsole(process),
                ReadInputFromConsole(process)
            };
        Task.WaitAny(tasks);
        PrintExceptions(tasks);

        static async Task PrintToConsole(RemoteProcess process)
        {
            char[] buffer = new char[1024];
            while (true)
            {
                (bool isError, int charsRead) = await process.ReadCharsAsync(buffer, buffer);
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
            using TextReader reader = CreateConsoleInReader();

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

        static TextReader CreateConsoleInReader()
        {
            if (!OperatingSystem.IsWindows() && !Console.IsInputRedirected)
            {
                // By default, Unix terminals are in CANON mode which means they return input line-by-line.
                // .NET disables CANON mode when its reading APIs are used.
                // This makes a cursor position read to disable CANON mode.
                _ = Console.CursorTop;
            }

            Stream stream;
            if (OperatingSystem.IsWindows())
            {
                throw new NotImplementedException();
            }
            else
            {
                // Directly read stdin so that the Console does not interpret the terminal sequences and we can send them as read.
                const int STDIN_FILENO = 0;
                SafeFileHandle handle = new SafeFileHandle(new IntPtr(STDIN_FILENO), ownsHandle: false);
                stream = new FileStream(handle, FileAccess.Read);
            }

            return new StreamReader(stream, Console.InputEncoding);
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
