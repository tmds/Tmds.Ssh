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

var destinationArg = new Argument<string>("destination")
{ Arity = ArgumentArity.ExactlyOne };
var commandArg = new Argument<string[]>("command")
{
    Description = "Command and arguments to execute on the remote host",
    Arity = ArgumentArity.ZeroOrMore
};
var forceTtyOption = new Option<bool>("-t")
{
    Description = "Force pseudo-terminal allocation"
};
var disableTtyOption = new Option<bool>("-T")
{
    Description = "Disable pseudo-terminal allocation"
};
var informationVerbosityOption = new Option<bool>("-v")
{
    Description = "Log at information level"
};
var debugVerbosityOption = new Option<bool>("-vv")
{
    Description = "Log at debug level"
};
var traceVerbosityOption = new Option<bool>("-vvv")
{
    Description = "Log at trace level"
};
var quietModeOption = new Option<bool>("-q")
{
    Description = "Suppress logging"
};
var sshConfigOptions = new Option<string[]>("-o")
{
    Description = $"Set an SSH Config option, for example: Ciphers=chacha20-poly1305@openssh.com.{Environment.NewLine}Supported options: {string.Join(", ", Enum.GetValues<SshConfigOption>().Select(o => o.ToString()))}",
    Arity = ArgumentArity.ZeroOrMore
};

var rootCommand = new RootCommand("An 'ssh'-like command implemented using Tmds.Ssh.");
rootCommand.Options.Add(forceTtyOption);
rootCommand.Options.Add(disableTtyOption);
rootCommand.Options.Add(sshConfigOptions);
rootCommand.Options.Add(informationVerbosityOption);
rootCommand.Options.Add(debugVerbosityOption);
rootCommand.Options.Add(traceVerbosityOption);
rootCommand.Options.Add(quietModeOption);

rootCommand.Arguments.Add(destinationArg);
rootCommand.Arguments.Add(commandArg);

rootCommand.SetAction(
    (ParseResult parseResult, CancellationToken ct) =>
    {
        bool forceTty = parseResult.GetValue(forceTtyOption);
        bool disableTty = parseResult.GetValue(disableTtyOption);
        bool informationVerbosity = parseResult.GetValue(informationVerbosityOption);
        bool debugVerbosity = parseResult.GetValue(debugVerbosityOption);
        bool traceVerbosity = parseResult.GetValue(traceVerbosityOption);
        bool quietMode = parseResult.GetValue(quietModeOption);
        string[] options = parseResult.GetValue(sshConfigOptions)!;
        string destination = parseResult.GetValue(destinationArg)!;
        string[] command = parseResult.GetValue(commandArg)!;
        return ExecuteAsync(destination, command, forceTty, disableTty, informationVerbosity, debugVerbosity, traceVerbosity, quietMode, options);
    });

ParseResult parseResult = rootCommand.Parse(args);
return await parseResult.InvokeAsync();

static async Task<int> ExecuteAsync(string destination, string[] command, bool forceTty, bool disableTty, bool informationVerbosity, bool debugVerbosity, bool traceVerbosity, bool quietMode, string[] options)
{
    LogLevel logLevel;
    if (quietMode)
    {
        logLevel = LogLevel.None;
    }
    else if (traceVerbosity)
    {
        logLevel = LogLevel.Trace;
    }
    else if (debugVerbosity)
    {
        logLevel = LogLevel.Debug;
    }
    else if (informationVerbosity)
    {
        logLevel = LogLevel.Information;
    }
    else
    {
        logLevel = LogLevel.Warning;
    }

    bool allocateTerminal = forceTty || (!disableTty && !Console.IsInputRedirected);

    using IDisposable? terminalOutputConfig = ConfigureTerminal(allocateTerminal);

    using ILoggerFactory? loggerFactory = logLevel == LogLevel.None ? null :
        LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(logLevel);
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
    if (logLevel != LogLevel.None)
    {
        PrintExceptions(tasks);
    }

    int exitCode = process.ExitCode;
    return exitCode;

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

static SshConfigSettings CreateSshConfigSettings(string[] options)
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

interface IStandardInputReader : IDisposable
{
    ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default);
}
