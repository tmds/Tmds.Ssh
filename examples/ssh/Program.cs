using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
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
        var sshConfigOptions = new Option<string[]>(new[] { "-o", "--option" },
            description: $"Set an SSH Config option, for example: Ciphers=chacha20-poly1305@openssh.com.{Environment.NewLine}Supported options: {string.Join(", ", Enum.GetValues<SshConfigOption>().Select(o => o.ToString()))}.")
        { Arity = ArgumentArity.ZeroOrMore };

        var rootCommand = new RootCommand("Execute a command on a remote system over SSH.");
        rootCommand.AddOption(sshConfigOptions);
        rootCommand.AddArgument(destinationArg);
        rootCommand.AddArgument(commandArg);
        rootCommand.SetHandler(ExecuteAsync, destinationArg, commandArg, sshConfigOptions);

        return rootCommand.InvokeAsync(args);
    }

    static async Task ExecuteAsync(string destination, string command, string[] options)
    {
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

        SshConfigOptions configOptions = CreateSshConfigOptions(options);

        using SshClient client = new SshClient(destination, configOptions, loggerFactory);

        using var process = await client.ExecuteAsync(command);
        Task[] tasks = new[]
        {
                PrintToConsole(process),
                ReadInputFromConsole(process)
            };
        Task.WaitAny(tasks);
        PrintExceptions(tasks);

        static async Task PrintToConsole(RemoteProcess process)
        {
            await foreach ((bool isError, string line) in process.ReadAllLinesAsync())
            {
                Console.WriteLine(line);
            }
        }

        static async Task ReadInputFromConsole(RemoteProcess process)
        {
            // note: Console doesn't have an async ReadLine that accepts a CancellationToken...
            await Task.Yield();
            var cancellationToken = process.ExecutionAborted;
            while (!cancellationToken.IsCancellationRequested)
            {
                string? line = Console.ReadLine();
                if (line == null)
                {
                    break;
                }
                await process.WriteLineAsync(line);
            }
        }

        static void PrintExceptions(Task[] tasks)
        {
            foreach (var task in tasks)
            {
                Exception? innerException = task.Exception?.InnerException;
                if (innerException is not null)
                {
                    System.Console.WriteLine("Exception:");
                    Console.WriteLine(innerException);
                }
            }
        }
    }

    private static SshConfigOptions CreateSshConfigOptions(string[] options)
    {
        SshConfigOptions configOptions = new SshConfigOptions(SshConfigOptions.DefaultConfigFilePaths);

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
        configOptions.Options = optionsDict;

        return configOptions;
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
