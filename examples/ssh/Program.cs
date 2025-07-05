using System;
using System.Collections.Generic;
using System.CommandLine;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Tmds.Ssh;

class Program
{
    static Task<int> Main(string[] args)
    {
        var destinationArg = new Argument<string>(name: "destination")
        { Arity = ArgumentArity.ExactlyOne };
        var commandArg = new Argument<string[]>(name: "command",
            description: "Command and arguments to execute on the remote host")
        { Arity = ArgumentArity.ZeroOrMore };
        var forceTtyOption = new Option<bool>(new[] { "-t" }, "Force pseudo-terminal allocation");
        var disableTtyOption = new Option<bool>(new[] { "-T" }, "Disable pseudo-terminal allocation");
        var sshConfigOptions = new Option<string[]>(new[] { "-o", "--option" },
            description: $"Set an SSH Config option, for example: Ciphers=chacha20-poly1305@openssh.com.{Environment.NewLine}Supported options: {string.Join(", ", Enum.GetValues<SshConfigOption>().Select(o => o.ToString()))}.")
        { Arity = ArgumentArity.ZeroOrMore };

        var rootCommand = new RootCommand("Execute a command on a remote system over SSH.");
        rootCommand.AddOption(forceTtyOption);
        rootCommand.AddOption(disableTtyOption);
        rootCommand.AddOption(sshConfigOptions);
        rootCommand.AddArgument(destinationArg);
        rootCommand.AddArgument(commandArg);
        rootCommand.SetHandler(ExecuteAsync, destinationArg, commandArg, forceTtyOption, disableTtyOption, sshConfigOptions);

        return rootCommand.InvokeAsync(args);
    }

    static async Task ExecuteAsync(string destination, string[] command, bool forceTty, bool disableTty, string[] options)
    {
        bool trace = IsEnvvarTrue("TRACE");
        bool log = trace || IsEnvvarTrue("LOG");

        bool allocateTerminal = forceTty || (!disableTty && !Console.IsInputRedirected);

        using IDisposable? terminalOutputConfig = ConfigureTerminal(allocateTerminal);

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

        using var process =
            command.Length == 0 ? await client.ExecuteShellAsync(executeOptions)
                                : await client.ExecuteAsync(string.Join(" ", command), executeOptions);

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
            using IStandardInputReader reader = CreateConsoleInReader(process.HasTerminal);

            char[] buffer = new char[100 * 1024];
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
                    Console.Error.WriteLine("Exception:");
                    Console.Error.WriteLine(innerException);
                }
            }
        }
    }

    static IDisposable? ConfigureTerminal(bool forTerminal)
    {
        if (Console.IsOutputRedirected)
        {
            return null;
        }

        if (OperatingSystem.IsWindows())
        {
            if (forTerminal)
            {
                const uint EnableStdOutFlags = WindowsInterop.ENABLE_VIRTUAL_TERMINAL_PROCESSING | WindowsInterop.DISABLE_NEWLINE_AUTO_RETURN;
                const uint DisableStdOutFlags = 0;
                return WindowsConsoleModeConfig.Configure(WindowsInterop.STD_OUTPUT_HANDLE, EnableStdOutFlags, DisableStdOutFlags);
            }
        }
        return null;
    }

    static IDisposable? UpdateTerminalSize(RemoteProcess process)
    {
        if (OperatingSystem.IsWindows())
        {
            return null;
        }
        else
        {
            return PosixSignalRegistration.Create(PosixSignal.SIGWINCH, ctx =>
            {
                try
                {
                    process.SetTerminalSize(Console.WindowWidth, Console.WindowHeight);
                }
                catch
                { }
            });
        }
    }

    static IStandardInputReader CreateConsoleInReader(bool forTerminal)
    {
        if (OperatingSystem.IsWindows())
        {
            return new WindowsStandardInputReader(forTerminal);
        }
        else
        {
            return new UnixStandardInputReader(forTerminal);
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

        configSettings.PasswordPrompt = (PasswordPromptContext ctx, CancellationToken ct) =>
        {
            if (ctx.IsBatchMode)
            {
                return ValueTask.FromResult((string?)null);
            }

            if (ctx.Attempt > 1)
            {
                Console.WriteLine("Permission denied, please try again.");
            }

            string prompt = $"{ctx.ConnectionInfo.UserName}@{ctx.ConnectionInfo.HostName}'s password: ";
            return PasswordPromptContext.ReadPasswordFromConsole(prompt);
        };

        configSettings.HostAuthentication = async (HostAuthenticationContext ctx, CancellationToken ct) =>
        {
            if (ctx.IsBatchMode)
            {
                return false;
            }

            if (Console.IsInputRedirected || Console.IsOutputRedirected)
            {
                return false;
            }

            PublicKey key = ctx.ConnectionInfo.ServerKey.Key;
            string hostName = ctx.ConnectionInfo.HostName;
            string keyType = key.Type.ToUpperInvariant();
            if (keyType.StartsWith("SSH-"))
            {
                keyType = keyType.Substring(4);
            }
            string fingerprint = key.SHA256FingerPrint;
            Console.WriteLine($"The authenticity of host '{hostName}' can't be established.");
            Console.WriteLine($"{keyType} key fingerprint is SHA256:{fingerprint}.");
            while (true)
            {
                Console.Write($"Are you sure you want to continue connecting (yes/no)? ");
                string? response = Console.ReadLine();
                switch (response)
                {
                    case "no":
                    case null:
                        return false;
                    case "yes":
                        return true;
                    default:
                        continue;
                }
            }
        };

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
