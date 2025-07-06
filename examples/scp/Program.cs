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

var filesArgs = new Argument<string[]>("files")
{
    Description = "Source(s) to copy to the target: <source>.. <target>",
    Arity = ArgumentArity.OneOrMore
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

var rootCommand = new RootCommand("Execute a command on a remote system over SSH.");
rootCommand.Options.Add(sshConfigOptions);
rootCommand.Options.Add(informationVerbosityOption);
rootCommand.Options.Add(debugVerbosityOption);
rootCommand.Options.Add(traceVerbosityOption);
rootCommand.Options.Add(quietModeOption);

rootCommand.Arguments.Add(filesArgs);

rootCommand.SetAction(
    parseResult =>
    {
        string[] files = parseResult.GetValue(filesArgs)!;
        bool informationVerbosity = parseResult.GetValue(informationVerbosityOption);
        bool debugVerbosity = parseResult.GetValue(debugVerbosityOption);
        bool traceVerbosity = parseResult.GetValue(traceVerbosityOption);
        bool quietMode = parseResult.GetValue(quietModeOption);
        string[] options = parseResult.GetValue(sshConfigOptions)!;
        return ExecuteAsync(files, informationVerbosity, debugVerbosity, traceVerbosity, quietMode, options);
    });

ParseResult parseResult = rootCommand.Parse(args);
return await parseResult.InvokeAsync();

static async Task<int> ExecuteAsync(string[] files, bool informationVerbosity, bool debugVerbosity, bool traceVerbosity, bool quietMode, string[] options)
{
    if (files.Length < 2)
    {
        Console.Error.WriteLine("files must at least include a <source> and a <target>.");
        return 1;
    }

    string[] sources = files[..^1].ToArray();
    string target = files[^1];
    Location targetLocation = Location.Parse(target);
    Location sourceLocation = Location.Parse(sources[0]);

    if (sources.Length > 1)
    {
        foreach (var source in sources)
        {
            Location currentSourceLocation = Location.Parse(source);
            if (currentSourceLocation.IsLocal != sourceLocation.IsLocal || currentSourceLocation.SshDestination != sourceLocation.SshDestination)
            {
                Console.Error.WriteLine("Cannot copy sources from different systems");
                return 1;
            }
        }
    }

    if (sourceLocation.IsLocal == true && targetLocation.IsLocal == true)
    {
        Console.Error.WriteLine("Cannot perform local copies.");
        return 1;
    }
    if (sourceLocation.IsLocal == false && targetLocation.IsLocal == false)
    {
        Console.Error.WriteLine("Cannot perform remote copies.");
        return 1;
    }

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

    using ILoggerFactory? loggerFactory = logLevel == LogLevel.None ? null :
        LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(logLevel);
        });

    string sshDestination = sourceLocation.SshDestination ?? targetLocation.SshDestination!;
    SshConfigSettings configSettings = CreateSshConfigSettings(options);
    using SshClient client = new SshClient(sshDestination, configSettings, loggerFactory);
    await client.ConnectAsync();
    using SftpClient sftpClient = await client.OpenSftpClientAsync();

    foreach (var source in sources)
    {
        sourceLocation = Location.Parse(source);

        if (sourceLocation.IsLocal)
        {
            bool isDirectory = Directory.Exists(sourceLocation.Path);

            if (isDirectory)
            {
                await sftpClient.CreateDirectoryAsync(targetLocation.Path);
                await sftpClient.UploadDirectoryEntriesAsync(sourceLocation.Path, targetLocation.Path);
            }
            else
            {
                await sftpClient.UploadFileAsync(sourceLocation.Path, targetLocation.Path);
            }
        }
        else
        {
            var attributes = await sftpClient.GetAttributesAsync(sourceLocation.Path, followLinks: true);
            if (attributes is null)
            {
                Console.Error.WriteLine($"Source '{sourceLocation.Path}' is not found.");
                return 1;
            }

            switch (attributes.FileType)
            {
                case UnixFileType.Directory:
                    Directory.CreateDirectory(targetLocation.Path);
                    await sftpClient.DownloadDirectoryEntriesAsync(sourceLocation.Path, targetLocation.Path);
                    break;
                case UnixFileType.RegularFile:
                    await sftpClient.DownloadFileAsync(sourceLocation.Path, targetLocation.Path);
                    break;
                default:
                    Console.Error.WriteLine($"Cannot copy file of type {attributes.FileType}.");
                    return 1;

            }
        }
    }

    return 0;
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

sealed class Location
{
    public bool IsLocal => SshDestination is null;
    public required string? SshDestination { get; init; }
    public required string Path { get; init; }

    public static Location Parse(string value)
    {
        int colonPos = value.IndexOf(':');
        if (colonPos != -1)
        {
            return new Location
            {
                SshDestination = value.Substring(0, colonPos),
                Path = value.Substring(colonPos + 1)
            };
        }
        else
        {
            return new Location
            {
                SshDestination = null,
                Path = value
            };
        }
    }
}
