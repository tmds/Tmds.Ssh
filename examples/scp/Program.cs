using System.CommandLine;
using Microsoft.Extensions.Logging;
using Tmds.Ssh;

var filesArgs = new Argument<string[]>("files")
{
    Description = $"Source(s) to copy to the target: <source>.. <target>.{Environment.NewLine}When there are multiple sources, the target is considered to be a directory.{Environment.NewLine}Otherwise the source is copied in the target directory if it exists, or created at the target path if it does not exist.",
    Arity = ArgumentArity.OneOrMore
};
var recursiveOption = new Option<bool>("-r")
{
    Description = "Copy directories"
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
var sshConfigOptions = new Option<string[]>("-o")
{
    Description = $"Set an SSH Config option, for example: Ciphers=chacha20-poly1305@openssh.com.{Environment.NewLine}Supported options: {string.Join(", ", Enum.GetValues<SshConfigOption>().Select(o => o.ToString()))}",
    Arity = ArgumentArity.ZeroOrMore
};

var rootCommand = new RootCommand("Execute a command on a remote system over SSH.");
rootCommand.Options.Add(sshConfigOptions);
rootCommand.Options.Add(recursiveOption);
rootCommand.Options.Add(informationVerbosityOption);
rootCommand.Options.Add(debugVerbosityOption);
rootCommand.Options.Add(traceVerbosityOption);

rootCommand.Arguments.Add(filesArgs);

rootCommand.SetAction(
    (ParseResult parseResult, CancellationToken ct) =>
    {
        string[] files = parseResult.GetValue(filesArgs)!;
        bool recursive = parseResult.GetValue(recursiveOption);
        bool informationVerbosity = parseResult.GetValue(informationVerbosityOption);
        bool debugVerbosity = parseResult.GetValue(debugVerbosityOption);
        bool traceVerbosity = parseResult.GetValue(traceVerbosityOption);
        string[] options = parseResult.GetValue(sshConfigOptions)!;
        return ExecuteAsync(files, recursive, informationVerbosity, debugVerbosity, traceVerbosity, options);
    });

ParseResult parseResult = rootCommand.Parse(args);
return await parseResult.InvokeAsync();

static async Task<int> ExecuteAsync(string[] files, bool recursive, bool informationVerbosity, bool debugVerbosity, bool traceVerbosity, string[] options)
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
    if (traceVerbosity)
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

    if (sourceLocation.IsLocal)
    {
        return await UploadAsync(sftpClient, sources, sourceLocation, targetLocation, recursive);
    }
    else
    {
        return await DownloadAsync(sftpClient, sources, sourceLocation, targetLocation, recursive);
    }
}

static async Task<int> DownloadAsync(SftpClient sftpClient, string[] sources, Location sourceLocation, Location targetLocation, bool recursive)
{
    bool skippedSources = false;
    bool targetIsDir = sources.Length > 1 || Directory.Exists(targetLocation.Path);

    foreach (var source in sources)
    {
        string sourcePath = Location.Parse(source).Path;

        var sourceAttributes = await sftpClient.GetAttributesAsync(sourcePath, followLinks: true);
        if (sourceAttributes is null)
        {
            Console.Error.WriteLine($"Source '{sourcePath}' is not found.");
            return 1;
        }

        string targetPath = targetLocation.Path;
        if (targetIsDir)
        {
            string filename = Path.GetFileName(sourcePath.TrimEnd('/'));
            targetPath = $"{targetPath}/{filename}";
        }
        Console.WriteLine($"{sourcePath} -> {targetPath}");

        switch (sourceAttributes.FileType)
        {
            case UnixFileType.Directory:
                if (!recursive)
                {
                    Console.Error.WriteLine($"Skipping directory '{sourcePath}' because the '-r' option is not specified.");
                    skippedSources = true;
                    continue;
                }
                await sftpClient.DownloadDirectoryEntriesAsync(sourcePath, targetPath, new() { TargetDirectoryCreation = TargetDirectoryCreation.Create, Overwrite = true });
                break;
            case UnixFileType.RegularFile:
                if (targetIsDir)
                {
                    Directory.CreateDirectory(targetLocation.Path);
                }
                await sftpClient.DownloadFileAsync(sourcePath, targetPath, overwrite: true);
                break;
            default:
                Console.Error.WriteLine($"Cannot copy file of type {sourceAttributes.FileType}.");
                return 1;
        }
    }

    return skippedSources ? 1 : 0;
}

static async Task<int> UploadAsync(SftpClient sftpClient, string[] sources, Location sourceLocation, Location targetLocation, bool recursive)
{
    bool skippedSources = false;
    bool targetIsDir = sources.Length > 1 ||
        (await sftpClient.GetAttributesAsync(targetLocation.Path, followLinks: true))?.FileType == UnixFileType.Directory;

    foreach (var source in sources)
    {
        string sourcePath = Location.Parse(source).Path;

        string targetPath = targetLocation.Path;
        if (targetIsDir)
        {
            string filename = Path.GetFileName(sourcePath.TrimEnd(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }));
            targetPath = $"{targetPath}/{filename}";
        }
        Console.WriteLine($"{sourcePath} -> {targetPath}");

        bool sourceIsDir = Directory.Exists(sourcePath);
        if (sourceIsDir)
        {
            if (!recursive)
            {
                Console.Error.WriteLine($"Skipping directory '{sourcePath}' because the '-r' option is not specified.");
                skippedSources = true;
                continue;
            }
            await sftpClient.UploadDirectoryEntriesAsync(sourcePath, targetPath, new() { TargetDirectoryCreation = TargetDirectoryCreation.Create, Overwrite = true });
        }
        else
        {
            if (targetIsDir)
            {
                await sftpClient.CreateDirectoryAsync(targetLocation.Path);
            }
            await sftpClient.UploadFileAsync(sourcePath, targetPath, overwrite: true);
        }
    }

    return skippedSources ? 1 : 0;
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
        return ReadPasswordFromConsole(prompt);
    };

    configSettings.HostAuthentication = (HostAuthenticationContext ctx, CancellationToken ct) =>
    {
        if (ctx.IsBatchMode)
        {
            return ValueTask.FromResult(false);
        }

        if (Console.IsInputRedirected || Console.IsOutputRedirected)
        {
            return ValueTask.FromResult(false);
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
                    return ValueTask.FromResult(false);
                case "yes":
                    return ValueTask.FromResult(true);
                default:
                    continue;
            }
        }
    };

    return configSettings;
}

static ValueTask<string?> ReadPasswordFromConsole(string? prompt = null)
{
    if (Console.IsInputRedirected || Console.IsOutputRedirected)
    {
        return ValueTask.FromResult((string?)null);
    }

    if (!string.IsNullOrEmpty(prompt))
    {
        Console.Write(prompt);
    }

    var password = string.Empty;
    ConsoleKeyInfo key;
    do
    {
        key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter)
        {
            Console.WriteLine();
            break;
        }
        else if (key.Key == ConsoleKey.Backspace)
        {
            if (password.Length > 0)
            {
                password = password[..^1];
            }
        }
        else if (key.KeyChar != '\0')
        {
            password += key.KeyChar;
        }
    } while (true);
    return ValueTask.FromResult((string?)password);
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
